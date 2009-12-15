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
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;

import com.google.code.jscep.EnrollmentFailureException;
import com.google.code.jscep.RequestPendingException;
import com.google.code.jscep.ScepException;
import com.google.code.jscep.operations.PkiOperation;
import com.google.code.jscep.pkcs7.Enveloper;
import com.google.code.jscep.pkcs7.Signer;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.response.PkiMessage;
import com.google.code.jscep.transport.Transport;

/**
 * This class represents a SCEP transaction, and provides a framework for 
 * performing operations.
 */
public class Transaction {
	private final TransactionId transId;
	private final Nonce senderNonce;
	private final KeyPair keyPair;
	private final Transport transport;
	private final Enveloper enveloper;
	private final Signer signer;

	Transaction(Transport transport, KeyPair keyPair, Enveloper enveloper, Signer signer) {
		this.transport = transport;
		this.keyPair = keyPair;
		this.transId = TransactionId.createTransactionId(keyPair);
		this.senderNonce = NonceFactory.nextNonce();
		this.enveloper = enveloper;
		this.signer = signer;
	}

	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws MalformedURLException if the SCEP URL is invalid.
	 * @throws IOException if any I/O error occurs.
	 * @throws RequestPendingException if manual intervention is required.
	 * @throws EnrollmentFailureException if the request could not be serviced.
	 * @throws GeneralSecurityException if any security error occurs.
	 * @throws ScepException 
	 */
	public CertStore performOperation(PkiOperation op) throws MalformedURLException, IOException, RequestPendingException, EnrollmentFailureException, GeneralSecurityException, ScepException {
		final byte[] msgData = op.getMessageData();
		final MessageType msgType = op.getMessageType();
		
		byte[] enveloped = enveloper.envelope(msgData);
		byte[] signedData = signer.sign(enveloped, msgType, transId, senderNonce);
		PkiRequest request = new PkiRequest(signedData, keyPair);
		PkiMessage response = transport.sendMessage(request);

		if (response.getTransactionId().equals(this.transId) == false) {
			throw new ScepException("Transaction ID Mismatch: Sent ["
					+ this.transId + "]; Received [" + response.getTransactionId()
					+ "]");
		}

		if (response.getRecipientNonce().equals(senderNonce) == false) {
			throw new ScepException("Sender Nonce Mismatch.  Sent ["
					+ this.senderNonce + "]; Received ["
					+ response.getRecipientNonce() + "]");
		}

		// TODO: Detect replay attacks.
		// 
		// http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
		response.getSenderNonce();

		if (response.getStatus().equals(PkiStatus.FAILURE)) {
			throw new EnrollmentFailureException(response.getFailInfo().toString());
		} else if (response.getStatus().equals(PkiStatus.PENDING)) {
			throw new RequestPendingException();
		} else {
			return response.getCertStore();
		}
	}
}
