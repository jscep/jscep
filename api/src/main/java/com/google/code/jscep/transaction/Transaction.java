/*
 * Copyright (c) 2009 David Grant
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
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;

import com.google.code.jscep.EnrollmentFailureException;
import com.google.code.jscep.RequestPendingException;
import com.google.code.jscep.operations.PkiOperation;
import com.google.code.jscep.pkcs7.DegenerateSignedData;
import com.google.code.jscep.pkcs7.DegenerateSignedDataParser;
import com.google.code.jscep.pkcs7.PkcsPkiEnvelope;
import com.google.code.jscep.pkcs7.PkcsPkiEnvelopeGenerator;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.pkcs7.PkiMessageGenerator;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents a SCEP transaction, and provides a framework for 
 * performing operations.
 */
public class Transaction {
	private static NonceQueue QUEUE = new NonceQueue(20);
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transaction");
	private final TransactionId transId;
	private final Nonce senderNonce;
	private final KeyPair keyPair;
	private final Transport transport;
	private final PkcsPkiEnvelopeGenerator envGenerator;
	private final PkiMessageGenerator msgGenerator;
	private final Set<Nonce> previousNonces = new HashSet<Nonce>();

	Transaction(Transport transport, KeyPair keyPair, PkcsPkiEnvelopeGenerator envGenerator, PkiMessageGenerator msgGenerator, String digestAlgorithm) {
		this.transport = transport;
		this.keyPair = keyPair;
		this.transId = TransactionId.createTransactionId(keyPair, digestAlgorithm);
		this.senderNonce = NonceFactory.nextNonce();
		this.envGenerator = envGenerator;
		this.msgGenerator = msgGenerator;
	}

	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 * @throws RequestPendingException if manual intervention is required.
	 * @throws EnrollmentFailureException if the request could not be serviced.
	 */
	public <T extends ASN1Encodable> CertStore performOperation(PkiOperation<T> op) throws IOException, EnrollmentFailureException, RequestPendingException {
		LOGGER.entering(getClass().getName(), "performOperation");
		
		msgGenerator.setMessageType(op.getMessageType());
		msgGenerator.setSenderNonce(senderNonce);
		msgGenerator.setTransactionId(transId);
		
		PkcsPkiEnvelope envelope = envGenerator.generate(op.getMessageData());
		PkiMessage msg = msgGenerator.generate(envelope);
		PkiRequest request = new PkiRequest(msg, keyPair);
		PkiMessage response = transport.sendMessage(request);

		if (response.getTransactionId().equals(this.transId) == false) {
			IOException ioe = new IOException("Transaction ID Mismatch: Sent ["
					+ this.transId + "]; Received [" + response.getTransactionId()
					+ "]");
			
			LOGGER.throwing(getClass().getName(), "performOperation", ioe);
			throw ioe;
		}

		// The requester SHOULD verify that the recipientNonce of the reply
		// matches the senderNonce it sent in the request.
		assert(response.getRecipientNonce().equals(senderNonce));

		// TODO: Detect replay attacks.
		// 
		// http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
		// Check the nonce has not been encountered before.
		assert(QUEUE.offer(response.getSenderNonce()));

		if (response.getStatus().equals(PkiStatus.FAILURE)) {
			EnrollmentFailureException efe = new EnrollmentFailureException(response.getFailInfo().toString());
			
			LOGGER.throwing(getClass().getName(), "performOperation", efe);
			throw efe;
		} else if (response.getStatus().equals(PkiStatus.PENDING)) {
			RequestPendingException rpe = new RequestPendingException();
			
			LOGGER.throwing(getClass().getName(), "performOperation", rpe);
			throw rpe;
		} else {
			final ASN1Encodable repMsgData = response.getPkcsPkiEnvelope().getMessageData();
			final DegenerateSignedDataParser parser = new DegenerateSignedDataParser();
			final DegenerateSignedData certRep = parser.parse(repMsgData);
			final CertStore cs = certRep.getCertStore();
			
			LOGGER.exiting(getClass().getName(), "performOperation", cs);
			return cs;
		}
	}
	
	@Override
	public String toString() {
		return "Transaction [" + transId + "]";
	}
}
