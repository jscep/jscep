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
package org.jscep.transaction;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.content.CertRepContentHandler;
import org.jscep.message.CertRep;
import org.jscep.message.GetCertInitial;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.operations.DelayablePkiOperation;
import org.jscep.pkcs7.SignedDataUtil;
import org.jscep.request.PKCSReq;
import org.jscep.state.StateMachine;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.Transport;
import org.jscep.util.LoggingUtil;
import org.jscep.x509.X509Util;


/**
 * This class represents a SCEP transaction, and provides a framework for 
 * performing operations.
 * <p>
 * The behaviour of this class changes in accordance with the possible valid states
 * for each transaction operation.  For enrollment operations, clients should inspect 
 * the {@link State} returned by the {@link #enrollCertificate(X509Certificate, KeyPair, char[])}
 * method or the state returned by the callable returned by {@link #getTask()}.
 * 
 * @author David Grant
 */
public class TransactionImpl implements Transaction {
	private static NonceQueue QUEUE = new NonceQueue(20);
	private static Logger LOGGER = LoggingUtil.getLogger(TransactionImpl.class);
	private final PrivateKey clientPrivateKey;
	private final Transport transport;
	private final X509Certificate serverCertificate;
	private final X509Certificate clientCertificate;
	private FailInfo failInfo;
	private CertStore certStore;
	private Callable<State> task;
	private State state = State.CERT_NON_EXISTANT;
	private final StateMachine stateMachine;

	public TransactionImpl(X509Certificate serverCertificate, X509Certificate clientCertificate, PrivateKey clientPrivateKey, Transport transport) {
		this.transport = transport;
		this.serverCertificate = serverCertificate;
		this.clientCertificate = clientCertificate;
		this.clientPrivateKey = clientPrivateKey;
		this.stateMachine = new StateMachine();
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
	 * If the state of this transaction is not {@link State#CERT_NON_EXISTANT},
	 * this method will throw an {@link IllegalStateException}.
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
	 * If the state of this transaction is not {@link State#CERT_ISSUED},
	 * this method will throw an {@link IllegalStateException}.
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
	 * If the state of this transaction is not {@link State#CERT_REQ_PENDING},
	 * this method will throw an {@link IllegalStateException}.
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
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 * @throws PkiOperationFailureException if the operation fails.
	 */
	public <T extends ASN1Encodable> State performOperation(PkiMessage<T> request) throws IOException {
		LOGGER.entering(getClass().getName(), "performOperation", request);
		
		stateMachine.updateState(request);
		
		PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(serverCertificate);
		PkiMessageEncoder encoder = new PkiMessageEncoder(clientPrivateKey, clientCertificate, envEncoder);
		
		CMSSignedData signedData = encoder.encode(request);
		CertRepContentHandler handler = new CertRepContentHandler();
		final CMSSignedData res = transport.sendMessage(new PKCSReq(signedData, handler));

		PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(clientPrivateKey);
		PkiMessageDecoder decoder = new PkiMessageDecoder(envDecoder);
		CertRep response = (CertRep) decoder.decode(res);

		stateMachine.updateState(response);
		
		validateExchange(request, response);
		
		if (response.getPkiStatus() == PkiStatus.FAILURE) {
			failInfo = response.getFailInfo();
			state = State.CERT_NON_EXISTANT;
		} else if (response.getPkiStatus() == PkiStatus.PENDING) {
			if (request instanceof DelayablePkiOperation<?>) {
				task = new InitialCertTask();
				state = State.CERT_REQ_PENDING;
			} else {
				throw new IllegalStateException(PkiStatus.PENDING + " not expected for " + request.getMessageType());
			}
		} else {
			certStore = extractCertStore(response);
			state = State.CERT_ISSUED;
		}
		
		return state;
	}

	private CertStore extractCertStore(CertRep response) throws IOException {
		final SignedData signedData = response.getMessageData();
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

	private void validateExchange(PkiMessage<?> req, CertRep res) throws IOException {
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
	
	private class InitialCertTask implements Callable<State> {
		public State call() throws IOException {
			if (state != State.CERT_REQ_PENDING) {
				throw new IllegalStateException();
			}
			final X509Name issuer = X509Util.toX509Name(serverCertificate.getIssuerX500Principal());
			final X509Name subject = X509Util.toX509Name(clientCertificate.getSubjectX500Principal());
			final IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
			final Nonce senderNonce = Nonce.nextNonce();
			final TransactionId transId = TransactionId.createTransactionId();
			final GetCertInitial getCert = new GetCertInitial(transId, senderNonce, ias);
			
			performOperation(getCert);
			
			return State.CERT_REQ_PENDING;
		}
	}
}
