/*
 * Copyright (c) 2009-2012 David Grant
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

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

import com.google.common.base.Objects;

public abstract class PkiResponse<T> extends PkiMessage<T> {
    private final Nonce recipientNonce;
    private final PkiStatus pkiStatus;
    private final FailInfo failInfo;

    /**
     * @param transId
     *            the transaction ID
     * @param messageType
     *            the message type
     * @param senderNonce
     *            the sender nonce
     * @param recipientNonce
     *            the recipient nonce
     * @param pkiStatus
     *            the PKI status
     * @param messageData
     *            the message data
     * @param failInfo
     *            the fail info enum
     */
    public PkiResponse(TransactionId transId, MessageType messageType,
            Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus,
            T messageData, FailInfo failInfo) {
        super(transId, messageType, senderNonce, messageData);

        this.recipientNonce = recipientNonce;
        this.pkiStatus = pkiStatus;
        this.failInfo = failInfo;
    }

    public Nonce getRecipientNonce() {
        return recipientNonce;
    }

    public PkiStatus getPkiStatus() {
        return pkiStatus;
    }

    public FailInfo getFailInfo() {
        if (pkiStatus != PkiStatus.FAILURE) {
            throw new IllegalStateException();
        }
        return failInfo;
    }

    @Override
    public T getMessageData() {
        if (pkiStatus != PkiStatus.SUCCESS) {
            throw new IllegalStateException();
        }
        return super.getMessageData();
    }

    public String toString() {
        return Objects.toStringHelper(this).add("pkiStatus", pkiStatus)
                .add("rcptNonce", recipientNonce).add("failInfo", failInfo)
                .toString();
    }
}
