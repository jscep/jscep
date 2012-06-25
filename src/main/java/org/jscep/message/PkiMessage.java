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

import java.util.HashMap;
import java.util.Map;

import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

import com.google.common.base.Objects;

/**
 * This class represents an abstract SCEP PkiMessage, which may be either a
 * request or response.
 *
 * @param <T> the MessageData for this message.
 */
public abstract class PkiMessage<T> {
    private final TransactionId transId;
    private final MessageType messageType;
    private final Nonce senderNonce;
    private final T messageData;

    public PkiMessage(TransactionId transId, MessageType messageType, Nonce senderNonce, T messageData) {
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

    public Map<String, Object> getAttributes() {
    	Map<String, Object> attr = new HashMap<String, Object>();
    	attr.put(ScepObjectIdentifiers.TRANS_ID, transId);
    	attr.put(ScepObjectIdentifiers.MESSAGE_TYPE, messageType);
    	attr.put(ScepObjectIdentifiers.SENDER_NONCE, senderNonce);

        return attr;
    }

    public String toString() {
        return Objects.toStringHelper(this)
                .add("type", messageType)
                .add("transId", transId)
                .add("msgData", messageData)
                .add("nonce", senderNonce)
                .toString();
    }
}
