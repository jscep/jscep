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
import java.security.cert.CertStore;

import org.jscep.content.CertRepContentHandler;
import org.jscep.content.InvalidContentException;
import org.jscep.content.InvalidContentTypeException;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.Request;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;

public abstract class Transaction {
    private final PkiMessageEncoder encoder;
    private final PkiMessageDecoder decoder;
    private final Transport transport;

    protected State state;
    protected FailInfo failInfo;
    protected CertStore certStore;

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

    public abstract State send() throws IOException, TransportException;

    public abstract TransactionId getId();

    protected byte[] send(final CertRepContentHandler handler, final Request req)
            throws TransportException, InvalidContentTypeException,
            InvalidContentException {
        return transport.sendRequest(req, handler);
    }

    protected PkiMessage<?> decode(byte[] res) throws IOException {
        return decoder.decode(res);
    }

    protected byte[] encode(final PkiMessage<?> message) throws IOException {
        return encoder.encode(message);
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
