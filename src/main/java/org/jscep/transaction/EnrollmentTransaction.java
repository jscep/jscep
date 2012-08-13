/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.CertRep;
import org.jscep.message.GetCertInitial;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkcsReq;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.message.PkiRequest;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.response.InvalidContentException;
import org.jscep.transport.response.InvalidContentTypeException;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents a SCEP transaction, and provides a framework for
 * performing operations.
 * <p/>
 * The behaviour of this class changes in accordance with the possible valid
 * states for each transaction operation. For enrollment operations, clients
 * should inspect the {@link State} returned by the {@link #send()} or
 * {@link #poll()}.
 * 
 * @author David Grant
 */
public class EnrollmentTransaction extends Transaction {
	private static final Logger LOGGER = LoggerFactory
			.getLogger(EnrollmentTransaction.class);
	private final TransactionId transId;
	private final PkiRequest<?> request;
	private static NonceQueue QUEUE = new NonceQueue();

	/**
	 * Constructs a new enrollment transaction.
	 * 
	 * @param transport the transport to use to send the transaction request.
	 * @param encoder the encoder to encode the transaction request.
	 * @param decoder the decoder to decode the transaction response.
	 * @param csr the signing request to send.
	 * @throws TransactionException if there is a problem creating the transaction ID.
	 */
	public EnrollmentTransaction(Transport transport, PkiMessageEncoder encoder,
			PkiMessageDecoder decoder, PKCS10CertificationRequest csr)
			throws TransactionException {
		super(transport, encoder, decoder);
		try {
			this.transId = TransactionId.createTransactionId(
					X509Util.getPublicKey(csr), "SHA-1");
		} catch (IOException e) {
			throw new TransactionException(e);
		} catch (InvalidKeySpecException e) {
			throw new TransactionException(e);
		}
		this.request = new PkcsReq(transId, Nonce.nextNonce(), csr);
	}
	
	/**
	 * Constructs a new enrollment transaction for polling.
	 * 
	 * @param transport the transport to use to send the transaction request.
	 * @param encoder the encoder to encode the transaction request.
	 * @param decoder the decoder to decode the transaction response.
	 * @param ias the issuer and subject to send.
	 * @param transId the transaction ID to use.
	 */
	public EnrollmentTransaction(Transport transport, PkiMessageEncoder encoder, PkiMessageDecoder decoder, IssuerAndSubject ias, TransactionId transId) {
		super(transport, encoder, decoder);
		
		this.transId = transId;
		this.request = new GetCertInitial(transId, Nonce.nextNonce(), ias);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public TransactionId getId() {
		return transId;
	}

	/**
	 * Sends the request to the SCEP server.
	 * 
	 * @return the resulting transaction state.
	 * @throws TransactionException if any error occurs.
	 */
	@Override
	public State send() throws TransactionException {
		CMSSignedData signedData;
		try {
			signedData = encode(request);
		} catch (MessageEncodingException e) {
			throw new TransactionException(e);
		}
		LOGGER.debug("Sending {}", signedData);
		PkiOperationResponseHandler handler = new PkiOperationResponseHandler();
		CMSSignedData res = send(handler, new PkiOperationRequest(signedData));
		LOGGER.debug("Received response {}", res);

		CertRep response;
		try {
			response = (CertRep) decode(res);
		} catch (MessageDecodingException e) {
			throw new TransactionException(e);
		}
		validateExchange(request, response);

		LOGGER.debug("Response: {}", response);

		if (response.getPkiStatus() == PkiStatus.FAILURE) {
			return failure(response.getFailInfo());
		} else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
			return success(extractCertStore(response));
		} else {
			return pending();
		}
	}

	private void validateExchange(PkiMessage<?> req, CertRep res)
			throws TransactionException {
		LOGGER.debug("Validating SCEP message exchange");

		if (!res.getTransactionId().equals(req.getTransactionId())) {
			throw new TransactionException("Transaction ID Mismatch");
		} else {
			LOGGER.debug("Matched transaction IDs");
		}

		// The requester SHOULD verify that the recipientNonce of the reply
		// matches the senderNonce it sent in the request.
		if (!res.getRecipientNonce().equals(req.getSenderNonce())) {
			throw new InvalidNonceException(
					"Response recipient nonce and request sender nonce are not equal");
		} else {
			LOGGER.debug("Matched request senderNonce and response recipientNonce");
		}

		if (res.getSenderNonce() == null) {
			LOGGER.warn("Response senderNonce is null");
			return;
		}

		// http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
		// Check that the nonce has not been encountered before.
		if (QUEUE.contains(res.getSenderNonce())) {
			throw new InvalidNonceException(
					"This nonce has been encountered before.  Possible replay attack?");
		} else {
			QUEUE.add(res.getSenderNonce());
			LOGGER.debug("{} has not been encountered before",
					res.getSenderNonce());
		}

		LOGGER.debug("SCEP message exchange validated successfully");
	}
}
