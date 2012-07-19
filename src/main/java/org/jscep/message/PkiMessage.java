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

import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

import com.google.common.base.Objects;

/**
 * This class represents an abstract SCEP PkiMessage, which may be either a
 * request or response.
 * 
 * @param <T>
 *            the MessageData for this message.
 */
public abstract class PkiMessage<T> {
    private final TransactionId transId;
    private final MessageType messageType;
    private final Nonce senderNonce;
    private final T messageData;

    public PkiMessage(TransactionId transId, MessageType messageType,
            Nonce senderNonce, T messageData) {
        this.transId = transId;
        this.messageType = messageType;
        this.senderNonce = senderNonce;
        this.messageData = messageData;
    }

    public TransactionId getTransactionId() {
        return transId;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public Nonce getSenderNonce() {
        return senderNonce;
    }

    public T getMessageData() {
        return messageData;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((messageData == null) ? 0 : messageData.hashCode());
        result = prime * result
                + ((messageType == null) ? 0 : messageType.hashCode());
        result = prime * result
                + ((senderNonce == null) ? 0 : senderNonce.hashCode());
        result = prime * result + ((transId == null) ? 0 : transId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PkiMessage<?> other = (PkiMessage<?>) obj;
        if (messageData == null) {
            if (other.messageData != null)
                return false;
        } else if (!messageData.equals(other.messageData))
            return false;
        if (messageType != other.messageType)
            return false;
        if (senderNonce == null) {
            if (other.senderNonce != null)
                return false;
        } else if (!senderNonce.equals(other.senderNonce))
            return false;
        if (transId == null) {
            if (other.transId != null)
                return false;
        } else if (!transId.equals(other.transId))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this).add("type", messageType)
                .add("transId", transId).add("msgData", messageData)
                .add("nonce", senderNonce).toString();
    }
}
