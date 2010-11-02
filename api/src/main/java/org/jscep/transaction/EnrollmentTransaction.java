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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.content.CertRepContentHandler;
import org.jscep.message.CertRep;
import org.jscep.message.GetCertInitial;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.pkcs7.SignedDataUtil;
import org.jscep.request.PKCSReq;
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
public class EnrollmentTransaction extends Transaction {
	private final TransactionId transId;
	private final org.jscep.message.PKCSReq request;
	private static NonceQueue QUEUE = new NonceQueue(20);
	private static Logger LOGGER = LoggingUtil.getLogger(EnrollmentTransaction.class);

	public EnrollmentTransaction(PkiMessageEncoder encoder, PkiMessageDecoder decoder, CertificationRequest csr) throws IOException {
		super(encoder, decoder);
		this.transId = TransactionId.createTransactionId(X509Util.getPublicKey(csr), "SHA-1");
		this.request = new org.jscep.message.PKCSReq(transId, Nonce.nextNonce(), csr);
	}
	
	@Override
	public TransactionId getId() {
		return transId;
	}
	
	/**
	 * Performs the given operation inside this transaction.
	 * 
	 * @param op the operation to perform.
	 * @return a certificate store, containing either certificates or CRLs.
	 * @throws IOException if any I/O error occurs.
	 * @throws PkiOperationFailureException if the operation fails.
	 */
	public State send(Transport transport) throws IOException {
		CMSSignedData signedData = encoder.encode(request);
		CertRepContentHandler handler = new CertRepContentHandler();
		final CMSSignedData res = transport.sendRequest(new PKCSReq(signedData, handler));

		CertRep response = (CertRep) decoder.decode(res);
		validateExchange(request, response);
		
		if (response.getPkiStatus() == PkiStatus.FAILURE) {
			failInfo = response.getFailInfo();
			state = State.CERT_NON_EXISTANT;
		} else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
			certStore = extractCertStore(response);
			state = State.CERT_ISSUED;
		} else {
			state = State.CERT_REQ_PENDING;
		}
		
		return state;
	}
	
	public State poll(Transport transport, X509Certificate issuer) throws IOException {
		X509Name issuerName = X509Util.toX509Name(issuer.getIssuerX500Principal());
		X509Name subjectName = request.getMessageData().getCertificationRequestInfo().getSubject();
		IssuerAndSubject ias = new IssuerAndSubject(issuerName, subjectName);
		final GetCertInitial pollReq = new GetCertInitial(transId, Nonce.nextNonce(), ias);
		CMSSignedData signedData = encoder.encode(pollReq);
		CertRepContentHandler handler = new CertRepContentHandler();
		final CMSSignedData res = transport.sendRequest(new PKCSReq(signedData, handler));
		
		CertRep response = (CertRep) decoder.decode(res);
		validateExchange(request, response);
		
		if (response.getPkiStatus() == PkiStatus.FAILURE) {
			failInfo = response.getFailInfo();
			state = State.CERT_NON_EXISTANT;
		} else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
			certStore = extractCertStore(response);
			state = State.CERT_ISSUED;
		} else {
			state = State.CERT_REQ_PENDING;
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
}
