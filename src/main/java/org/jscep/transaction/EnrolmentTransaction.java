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

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.content.CertRepContentHandler;
import org.jscep.message.*;
import org.jscep.request.PKCSReq;
import org.jscep.transport.Transport;
import org.jscep.util.LoggingUtil;
import org.jscep.x509.X509Util;
import org.slf4j.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;


/**
 * This class represents a SCEP transaction, and provides a framework for
 * performing operations.
 * <p/>
 * The behaviour of this class changes in accordance with the possible valid states
 * for each transaction operation.  For enrolment operations, clients should inspect
 * the {@link State} returned by the {@link #send()} or {@link #poll()}.
 *
 * @author David Grant
 */
public class EnrolmentTransaction extends Transaction {
    private static Logger LOGGER = LoggingUtil.getLogger(EnrolmentTransaction.class);
    private final TransactionId transId;
    private final org.jscep.message.PKCSReq request;
    private static NonceQueue QUEUE = new NonceQueue(20);
    private X509Certificate issuer;

    public EnrolmentTransaction(Transport transport, PkiMessageEncoder encoder, PkiMessageDecoder decoder, CertificationRequest csr) throws IOException {
        super(transport, encoder, decoder);
        this.transId = TransactionId.createTransactionId(X509Util.getPublicKey(csr), "SHA-1");
        this.request = new org.jscep.message.PKCSReq(transId, Nonce.nextNonce(), csr);
    }

    @Override
    public TransactionId getId() {
        return transId;
    }

    /**
     * Performs a certificate enrolment for the CSR given in the constructor.
     *
     * @return the resulting transaction state.
     * @throws IOException if any I/O error occurs.
     */
    public State send() throws IOException {
        CMSSignedData signedData;
		try {
			signedData = new CMSSignedData(encoder.encode(request));
		} catch (CMSException e) {
			throw new IOException(e);
		}
        LOGGER.debug("Sending {}", signedData);
        CertRepContentHandler handler = new CertRepContentHandler();
        final byte[] res = transport.sendRequest(new PKCSReq(signedData.getEncoded()), handler);
        LOGGER.debug("Received response {}", res);

        CertRep response = (CertRep) decoder.decode(res);
        validateExchange(request, response);

        LOGGER.debug("Response: {}", response);

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

    /**
     * Polls the SCEP server for an update on the enrolment operation.
     *
     * @return the resulting transaction state.
     * @throws IOException if any I/O error occurs.
     */
    public State poll() throws IOException {
        X509Name issuerName = X509Util.toX509Name(issuer.getSubjectX500Principal());
        X509Name subjectName = request.getMessageData().getCertificationRequestInfo().getSubject();
        IssuerAndSubject ias = new IssuerAndSubject(issuerName, subjectName);
        final GetCertInitial pollReq = new GetCertInitial(transId, Nonce.nextNonce(), ias);
        byte[] signedData = encoder.encode(pollReq);
        CertRepContentHandler handler = new CertRepContentHandler();
        final byte[] res = transport.sendRequest(new PKCSReq(signedData), handler);

        CertRep response = (CertRep) decoder.decode(res);
        validateExchange(pollReq, response);

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
        try {
            CMSSignedData signedData = new CMSSignedData(response.getMessageData());
            return signedData.getCertificatesAndCRLs("Collection", (String) null);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        } catch (CMSException e) {
            throw new IOException(e);
        }
    }

    private void validateExchange(PkiMessage<?> req, CertRep res) throws IOException {
        LOGGER.debug("Validating SCEP message exchange");

        if (!res.getTransactionId().equals(req.getTransactionId())) {
            throw new IOException("Transaction ID Mismatch");
        } else {
            LOGGER.debug("Matched transaction IDs");
        }

        // The requester SHOULD verify that the recipientNonce of the reply
        // matches the senderNonce it sent in the request.
        if (!res.getRecipientNonce().equals(req.getSenderNonce())) {
            throw new InvalidNonceException("Response recipient nonce and request sender nonce are not equal");
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
            throw new InvalidNonceException("This nonce has been encountered before.  Possible replay attack?");
        } else {
            QUEUE.offer(res.getSenderNonce());
            LOGGER.debug("Nonce has not been encountered before");
        }

        LOGGER.debug("SCEP message exchange validated successfully");
    }

    public void setIssuer(X509Certificate ca) {
        issuer = ca;
    }
}
