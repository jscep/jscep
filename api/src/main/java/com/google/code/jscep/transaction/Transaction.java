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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.X509Name;

import com.google.code.jscep.PKIOperationFailureException;
import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.operations.DelayablePKIOperation;
import com.google.code.jscep.operations.GetCertInitial;
import com.google.code.jscep.operations.PKIOperation;
import com.google.code.jscep.pkcs7.MessageData;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.pkcs7.PkiMessageGenerator;
import com.google.code.jscep.pkcs7.SignedDataParser;
import com.google.code.jscep.request.PKCSReq;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;
import com.google.code.jscep.util.SignedDataUtil;

/**
 * This class represents a SCEP transaction, and provides a framework for 
 * performing operations.
 * 
 * @author David Grant
 */
public class Transaction {
	private static NonceQueue QUEUE = new NonceQueue(20);
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transaction");
	private final KeyPair keyPair;
	private final Transport transport;
	private final PkiMessageGenerator msgGenerator;
	private final X509Certificate issuer;
	private final X509Certificate subject;
	private final String digestAlgorithm;

	Transaction(Transport transport, KeyPair keyPair, PkiMessageGenerator msgGenerator, String digestAlgorithm, X509Certificate issuer, X509Certificate subject) {
		this.transport = transport;
		this.keyPair = keyPair;
		this.digestAlgorithm = digestAlgorithm;
		this.msgGenerator = msgGenerator;
		this.issuer = issuer;
		this.subject = subject;
	}

	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 */
	public <T extends DEREncodable> CertStore performOperation(DelayablePKIOperation<T> op, long interval) throws IOException, PKIOperationFailureException {
		LOGGER.entering(getClass().getName(), "performOperation", new Object[] {op, interval});
		
		msgGenerator.setMessageType(op.getMessageType());
		msgGenerator.setSenderNonce(Nonce.nextNonce());
		msgGenerator.setTransactionId(TransactionId.createTransactionId(keyPair, digestAlgorithm));
		msgGenerator.setMessageData(MessageData.getInstance(op.getMessage()));
		
		PkiMessage req = msgGenerator.generate();
		PkiMessage res = transport.sendMessage(new PKCSReq(req, keyPair));

		validateResponse(req, res);

		final X509Name issuerName = X509CertificateFactory.toX509Name(issuer.getIssuerX500Principal());
		final X509Name subjectName = X509CertificateFactory.toX509Name(subject.getSubjectX500Principal());
		final GetCertInitial getCert = new GetCertInitial(issuerName, subjectName);
		final PkiMessageGenerator generator = msgGenerator.clone();
		generator.setMessageType(MessageType.GetCertInitial);
		generator.setMessageData(MessageData.getInstance(getCert.getMessage()));
		
		while (res.getPkiStatus() == PkiStatus.PENDING) {
			try {
				// Convert to milliseconds.
				Thread.sleep(interval * 1000L);
			} catch (InterruptedException e) {
				// TODO
				throw new RuntimeException(e);
			}
			
			generator.setSenderNonce(Nonce.nextNonce());
			req = generator.generate();
			res = transport.sendMessage(new PKCSReq(req, keyPair));
		}
		if (res.getPkiStatus() == PkiStatus.FAILURE) {
			throw new PKIOperationFailureException(res.getFailInfo());
		} else {
			return extractCertStore(res);
		}
	}
	
	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 * @throws PKIOperationFailureException if the operation fails.
	 */
	public <T extends DEREncodable> CertStore performOperation(PKIOperation<T> op) throws IOException, PKIOperationFailureException {
		LOGGER.entering(getClass().getName(), "performOperation", op);
		
		msgGenerator.setMessageType(op.getMessageType());
		msgGenerator.setSenderNonce(Nonce.nextNonce());
		msgGenerator.setTransactionId(TransactionId.createTransactionId(keyPair, digestAlgorithm));
		msgGenerator.setMessageData(MessageData.getInstance(op.getMessage()));
		
		final PkiMessage req = msgGenerator.generate();
		final PkiMessage res = transport.sendMessage(new PKCSReq(req, keyPair));

		validateResponse(req, res);

		if (res.getPkiStatus() == PkiStatus.FAILURE) {
			throw new PKIOperationFailureException(res.getFailInfo());
		} else if (res.getPkiStatus() == PkiStatus.PENDING) {
			throw new IllegalStateException(PkiStatus.PENDING + " not expected.");
		} else {
			return extractCertStore(res);
		}
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

	private void validateResponse(PkiMessage req, PkiMessage res) throws IOException {
		if (res.getTransactionId().equals(req.getTransactionId()) == false) {
			IOException ioe = new IOException("Transaction ID Mismatch: Sent ["
					+ req.getTransactionId() + "]; Received [" + res.getTransactionId()
					+ "]");
			
			LOGGER.throwing(getClass().getName(), "performOperation", ioe);
			throw ioe;
		}

		// The requester SHOULD verify that the recipientNonce of the reply
		// matches the senderNonce it sent in the request.
		if (res.getRecipientNonce().equals(req.getSenderNonce()) == false) {
			throw new InvalidNonceException("Response recipient nonce and request sender nonce are not equal");
		}

		// http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
		// Check that the nonce has not been encountered before.
		if (QUEUE.contains(res.getSenderNonce())) {
			throw new InvalidNonceException("This nonce has been encountered before.  Possible replay attack?");
		} else {
			QUEUE.offer(res.getSenderNonce());
		}
	}
	
	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder();
		
		sb.append("Transaction [\n");
//		sb.append("\ttransactionId: " + transId + "\n");
		sb.append("]");
		
		return sb.toString();
	}
}
