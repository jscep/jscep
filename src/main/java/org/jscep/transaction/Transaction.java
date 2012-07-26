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

import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSSignedData;
import org.jscep.message.CertRep;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.CertStoreUtils;

public abstract class Transaction {
    private final PkiMessageEncoder encoder;
    private final PkiMessageDecoder decoder;
    private final Transport transport;

    private State state;
    private FailInfo failInfo;
    private CertStore certStore;

    public Transaction(Transport transport, PkiMessageEncoder encoder,
            PkiMessageDecoder decoder) {
        this.transport = transport;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    /**
     * Retrieve the reason for failure.
     * 
     * @return the reason for failure.
     */
    public FailInfo getFailInfo() {
        if (state != State.CERT_NON_EXISTANT) {
            throw new IllegalStateException(
                    "No failure has been received.  Check state!");
        }
        return failInfo;
    }

    public CertStore getCertStore() {
        if (state != State.CERT_ISSUED) {
            throw new IllegalStateException(
                    "No certstore has been received.  Check state!");
        }
        return certStore;
    }

    public abstract State send() throws TransactionException;

    public abstract TransactionId getId();

    protected CMSSignedData send(final PkiOperationResponseHandler handler,
            final Request req) throws TransactionException {
        try {
            return transport.sendRequest(req, handler);
        } catch (TransportException e) {
            throw new TransactionException(e);
        }
    }

    protected PkiMessage<?> decode(CMSSignedData res)
            throws MessageDecodingException {
        return decoder.decode(res);
    }

    protected CMSSignedData encode(final PkiMessage<?> message)
            throws MessageEncodingException {
        return encoder.encode(message);
    }

    protected State pending() {
        this.state = State.CERT_REQ_PENDING;
        return state;
    }

    protected State failure(FailInfo failInfo) {
        this.failInfo = failInfo;
        this.state = State.CERT_NON_EXISTANT;

        return state;
    }

    protected State success(CertStore certStore) {
        this.certStore = certStore;
        this.state = State.CERT_ISSUED;

        return state;
    }

    protected CertStore extractCertStore(CertRep response) {
        CMSSignedData signedData = response.getMessageData();

        return CertStoreUtils.fromSignedData(signedData);
    }

    /**
     * This class represents the state of a transaction.
     * 
     * @author David Grant
     */
    public static enum State {
        /**
         * The transaction is a pending state.
         */
        CERT_REQ_PENDING,
        /**
         * The transaction is in a failed state.
         * <p/>
         * Clients should use {@link Transaction#getFailInfo()} to retrieve the
         * failure reason.
         */
        CERT_NON_EXISTANT,
        /**
         * The transaction has succeeded.
         * <p/>
         * Clients should use {@link Transaction#getCertStore()} to retrieve the
         * enrolled certificates.
         */
        CERT_ISSUED,
    }
}
