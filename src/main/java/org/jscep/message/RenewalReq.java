/*
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
package org.jscep.message;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents {@code PKCSReq} {@code pkiMessage}, which wraps a
 * PKCS #10 {@code CertificationRequest} object.
 */
public class RenewalReq extends PkiRequest<PKCS10CertificationRequest> {
    /**
     * Creates a new {@code RenewalReq} instance.
     *
     * @param transId
     *            the transaction ID for this request.
     * @param senderNonce
     *            the nonce for this request.
     * @param messageData
     *            the {@code CertificationRequest} to use in enrollment.
     */
    public RenewalReq(final TransactionId transId, final Nonce senderNonce,
            final PKCS10CertificationRequest messageData) {
        super(transId, MessageType.RENEWAL_REQ, senderNonce, messageData);
    }
}
