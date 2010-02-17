/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.google.code.jscep.transaction;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.X509Name;

import com.google.code.jscep.PKIOperationFailureException;
import com.google.code.jscep.operations.DelayablePKIOperation;
import com.google.code.jscep.operations.GetCRL;
import com.google.code.jscep.operations.GetCert;
import com.google.code.jscep.operations.GetCertInitial;
import com.google.code.jscep.operations.PKIOperation;
import com.google.code.jscep.pkcs7.MessageData;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.pkcs7.PkiMessageGenerator;
import com.google.code.jscep.pkcs7.SignedDataParser;
import com.google.code.jscep.pkcs7.SignedDataUtil;
import com.google.code.jscep.request.PKCSReq;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;
import com.google.code.jscep.x509.X509Util;

/**
 * This class represents a SCEP transaction, and provides a framework for 
 * performing operations.
 * <p>
 * The behaviour of this class changes in accordance with the possible valid states
 * for each transaction operation.  For enrollment operations, clients should obtain
 * the current state using {@see #getState()}, and perform the steps required by
 * that outcome.  For all other operations, the method will return the required
 * type unless the server rejects the operation, in which case a 
 * {@see PkiOperationFailureException} will be thrown.
 * 
 * @author David Grant
 */
public class Transaction {
	private static NonceQueue QUEUE = new NonceQueue(20);
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transaction");
	private final KeyPair clientKeyPair;
	private final Transport transport;
	private final PkiMessageGenerator msgGenerator;
	private final X509Certificate serverCertificate;
	private final X509Certificate clientCertificate;
	private final TransactionId transId;
	private final X509Certificate issuerCertificate;
	private String digestAlg;
	private FailInfo failInfo;
	private CertStore certStore;
	private Callable<State> task;
	private State state = State.CERT_NON_EXISTANT;

	Transaction(X509Certificate issuerCertificate, X509Certificate serverCertificate, X509Certificate clientCertificate, KeyPair clientKeyPair, String digestAlg, String cipherAlg, Transport transport) {
		this.issuerCertificate = issuerCertificate;
		this.transport = transport;
		
		this.serverCertificate = serverCertificate;
		this.clientCertificate = clientCertificate;
		this.clientKeyPair = clientKeyPair;
		this.transId = TransactionId.createTransactionId(clientKeyPair, digestAlg);
		this.digestAlg = digestAlg;
		
		msgGenerator = new PkiMessageGenerator();
		msgGenerator.setTransactionId(transId);
		msgGenerator.setMessageDigest(digestAlg);
		msgGenerator.setSigner(clientCertificate);
		msgGenerator.setKeyPair(clientKeyPair);
		msgGenerator.setCipherAlgorithm(cipherAlg);
		msgGenerator.setRecipient(serverCertificate);
	}
	
	/**
	 * Returns the current state of this transaction.
	 * 
	 * @return the current state.
	 */
	public State getState() {
		return state;
	}
	
	
	/**
	 * Returns the failure reason explaining why the server rejected this transaction.
	 * <p>
	 * If the state of this transaction is not {@see Transaction.State.FAILED},
	 * this method will throw an IllegalStateException.
	 * 
	 * @return the failure reason.
	 * @throws IllegalStateException
	 */
	public FailInfo getFailureReason() {
		if (state != State.CERT_NON_EXISTANT) {
			throw new IllegalStateException();
		}
		return failInfo;
	}
	
	/**
	 * Returns the CertStore that was the outcome of this transaction.
	 * <p>
	 * If the state of this transaction is not {@see Transaction.State.SUCCEEDED},
	 * this method will throw an IllegalStateException.
	 * 
	 * @return the certificate store.
	 * @throws IllegalStateException
	 */
	public CertStore getCertStore() {
		if (state != State.CERT_ISSUED) {
			throw new IllegalStateException();
		}
		return certStore;
	}
	
	/**
	 * Returns the task that may be used to advance this transaction.
	 * <p>
	 * If the state of this transaction is not {@see Transaction.State.PENDING},
	 * this method will throw an IllegalStateException.
	 * 
	 * @return the task.
	 * @throws IllegalStateException
	 */
	public Callable<State> getTask() {
		if (state != State.CERT_REQ_PENDING) {
			throw new IllegalStateException();
		}
		return task;
	}
	
	/**
     * Retrieves the certificate with the provided serial number as issued by the
     * server CA. 
     *  
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws PKIOperationFailureException if the transaction is rejected.
     */
	public List<X509Certificate> getCertificate(BigInteger serial) throws IOException, PKIOperationFailureException {
		X509Certificate ca = issuerCertificate;
		final GetCert req = new GetCert(ca.getIssuerX500Principal(), serial);
		performOperation(req);
		
		if (getState() == State.CERT_ISSUED) {
			try {
				return getCertificates(getCertStore().getCertificates(null));
			} catch (CertStoreException e) {
				throw new RuntimeException(e);
			}
		} else if (getState() == State.CERT_REQ_PENDING) {
			throw new IllegalStateException();
		} else {
			throw new PKIOperationFailureException(getFailureReason());
		}
	}
	
	private List<X509Certificate> getCertificates(Collection<? extends Certificate> certs) {
    	final List<X509Certificate> x509 = new ArrayList<X509Certificate>();
    	
    	for (Certificate cert : certs) {
    		x509.add((X509Certificate) cert);
    	}
    	
    	return x509;
    }
	
	/**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.2.4
     */
    private boolean supportsDistributionPoints(X509Certificate issuerCertificate) {
    	return issuerCertificate.getExtensionValue("2.5.29.31") != null;
    }
	
    /**
     * Retrieves the Certificate Revocation List for the server CA.
     *  
     * @return the CRL.
     * @throws IOException if any I/O error occurs.
     * @throws PKIOperationFailureException if the transaction is rejected.
     */
	public List<X509CRL> getCRL() throws IOException, PKIOperationFailureException {
		X509Certificate ca = issuerCertificate;
		
		if (supportsDistributionPoints(issuerCertificate)) {
			throw new UnsupportedOperationException();
		}
		
		final GetCRL req = new GetCRL(ca.getIssuerX500Principal(), ca.getSerialNumber());
		performOperation(req);
		
		if (getState() == State.CERT_ISSUED) {
			try {
				return getCRLs(getCertStore().getCRLs(null));
			} catch (CertStoreException e) {
				throw new RuntimeException(e);
			}
		} else if (getState() == State.CERT_REQ_PENDING) {
			throw new IllegalStateException();
		} else {
			throw new PKIOperationFailureException(getFailureReason());
		}
	}
	
	private List<X509CRL> getCRLs(Collection<? extends CRL> crls) {
    	final List<X509CRL> x509 = new ArrayList<X509CRL>();
        
        for (CRL crl : crls) {
        	x509.add((X509CRL) crl);
        }
        
        return x509;
    }

	/**
	 * Attempts to enroll the provided subject certificate with the configured CA server.
	 * 
	 * @param subject the subject certificate.
	 * @param subjectKeyPair the subject key pair.
	 * @param password the password to authenticate the operation.
	 * @return the resulting state.
	 * @throws IOException if any I/O error occurs.
	 */
	public State enrollCertificate(X509Certificate subject, KeyPair subjectKeyPair, char[] password) throws IOException {
		final com.google.code.jscep.operations.PKCSReq req = new com.google.code.jscep.operations.PKCSReq(subjectKeyPair, subject, digestAlg, password);
		return performOperation(req);
	}
	
	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 * @throws PKIOperationFailureException if the operation fails.
	 */
	private <T extends DEREncodable> State performOperation(PKIOperation<T> op) throws IOException {
		LOGGER.entering(getClass().getName(), "performOperation", op);
		
		msgGenerator.setMessageType(op.getMessageType());
		msgGenerator.setSenderNonce(Nonce.nextNonce());
		msgGenerator.setMessageData(MessageData.getInstance(op.getMessage()));
		
		final PkiMessage req = msgGenerator.generate();
		final PkiMessage res = transport.sendMessage(new PKCSReq(req, clientKeyPair));

		validateExchange(req, res);
		
		if (res.getPkiStatus() == PkiStatus.FAILURE) {
			failInfo = res.getFailInfo();
			state = State.CERT_NON_EXISTANT;
		} else if (res.getPkiStatus() == PkiStatus.PENDING) {
			if (op instanceof DelayablePKIOperation<?>) {
				task = new InitialCertTask();
				state = State.CERT_REQ_PENDING;
			} else {
				throw new IllegalStateException(PkiStatus.PENDING + " not expected.");
			}
		} else {
			certStore = extractCertStore(res);
			state = State.CERT_ISSUED;
		}
		
		return state;
	}

	private CertStore extractCertStore(PkiMessage response) throws IOException {
		final MessageData repMsgData = response.getPkcsPkiEnvelope().getMessageData();
		final SignedDataParser parser = new SignedDataParser();
		final SignedData signedData = parser.parse(repMsgData.getContent());
		CertStore cs;
		try {
			cs = SignedDataUtil.extractCertStore(signedData);
		} catch (GeneralSecurityException e) {
			IOException ioe = new IOException(e);
			
			LOGGER.throwing(getClass().getName(), "getContent", ioe);
			throw ioe;
		}
		return cs;
	}

	private void validateExchange(PkiMessage req, PkiMessage res) throws IOException {
		if (res.getTransactionId().equals(req.getTransactionId()) == false) {
			final IOException ioe = new IOException("Transaction ID Mismatch");
			
			LOGGER.throwing(getClass().getName(), "validateResponse", ioe);
			throw ioe;
		}

		// The requester SHOULD verify that the recipientNonce of the reply
		// matches the senderNonce it sent in the request.
		if (res.getRecipientNonce().equals(req.getSenderNonce()) == false) {
			InvalidNonceException e = new InvalidNonceException("Response recipient nonce and request sender nonce are not equal");
			
			LOGGER.throwing(getClass().getName(), "validateResponse", e);
			throw e;
		}

		// http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
		// Check that the nonce has not been encountered before.
		if (QUEUE.contains(res.getSenderNonce())) {
			InvalidNonceException e = new InvalidNonceException("This nonce has been encountered before.  Possible replay attack?");
			
			LOGGER.throwing(getClass().getName(), "validateResponse", e);
			throw e;
		} else {
			QUEUE.offer(res.getSenderNonce());
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		
		sb.append("Transaction [\n");
		sb.append("\ttransactionId: " + transId + "\n");
		sb.append("]");
		
		return sb.toString();
	}
	
	private class InitialCertTask implements Callable<State> {
		public State call() throws IOException {
			if (state != State.CERT_REQ_PENDING) {
				throw new IllegalStateException();
			}
			final X509Name issuerName = X509Util.toX509Name(serverCertificate.getIssuerX500Principal());
			final X509Name subjectName = X509Util.toX509Name(clientCertificate.getSubjectX500Principal());
			final GetCertInitial getCert = new GetCertInitial(issuerName, subjectName);
			
			performOperation(getCert);
			
			return State.CERT_REQ_PENDING;
		}
	}
	
	/**
	 * This class represents the state of a transaction.
	 * 
	 * @author David Grant
	 */
	public enum State {
		/**
		 * The transaction is a pending state.  Clients should obtain
		 * a task to execute to proceed.
		 * <p>
		 * See {@link Transaction#getTask()}
		 */
		CERT_REQ_PENDING,
		/**
		 * The transaction is in a failed state.  Clients should obtain
		 * the failure reason.
		 * <p>
		 * See {@link Transaction#getFailureReason()}
		 */
		CERT_NON_EXISTANT,
		/**
		 * The transaction has succeeded.  Clients should obtain the certificate
		 * store.
		 * <p>
		 * See {@link Transaction#getCertStore()}
		 */
		CERT_ISSUED,
	}
	
	/**
	 * Creates a new transaction.
	 * 
	 * @param issuerCertificate the certificate of the issuer (CA).
	 * @param serverCertificate the server certificate.
	 * @param clientCertificate the client certificate.
	 * @param clientKeyPair the key pair for the client.
	 * @param capabilities the server capabilities.
	 * @param transport the transport to use for this transaction.
	 * @return a new transaction.
	 */
	public static Transaction createTransaction(X509Certificate issuerCertificate, X509Certificate serverCertificate, X509Certificate clientCertificate, KeyPair clientKeyPair, String digestAlg, String cipherAlg, Transport transport) {
		LOGGER.entering(Transaction.class.getName(), "createTransaction");
		
		Transaction t = new Transaction(issuerCertificate, serverCertificate, clientCertificate, clientKeyPair, digestAlg, cipherAlg, transport);
		
		LOGGER.exiting (Transaction.class.getName(), "createTransaction", t);
		return t;
	}
}
