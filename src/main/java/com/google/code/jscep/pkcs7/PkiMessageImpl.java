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

package com.google.code.jscep.pkcs7;

import java.util.logging.Logger;

import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

/**
 * Implementation of {@link PkiMessage} that uses Bouncy Castle.
 */
class PkiMessageImpl implements PkiMessage {
	private static Logger LOGGER = Logger.getLogger("com.google.code.jscep.pkcs7");
	private TransactionId transId;
	private PkiStatus pkiStatus;
	private Nonce recipientNonce;
	private Nonce senderNonce;
	private FailInfo failInfo;
	private MessageType msgType;
	private byte[] encoded;
	private PkcsPkiEnvelope pkcsPkiEnvelope;
	
	PkiMessageImpl() {
		
	}

	void setPkcsPkiEnvelope(PkcsPkiEnvelope envelope) {
		this.pkcsPkiEnvelope = envelope;
	}
	
	public PkcsPkiEnvelope getPkcsPkiEnvelope() {
		return pkcsPkiEnvelope;
	}
	
	void setFailInfo(FailInfo failInfo) {
		this.failInfo = failInfo;
	}
	
	public FailInfo getFailInfo() {
		return failInfo;
	}
	
	void setStatus(PkiStatus status) {
		this.pkiStatus = status;
	}
	
	public PkiStatus getStatus() {
		return pkiStatus;
	}
	
	void setRecipientNonce(Nonce nonce) {
		this.recipientNonce = nonce;
	}
	
	public Nonce getRecipientNonce() {
		return recipientNonce;
	}
	
	public Nonce getSenderNonce() {
		return senderNonce;
	}
	
	public void setSenderNonce(Nonce senderNonce) {
		this.senderNonce = senderNonce;
	}
	
	void setTransactionId(TransactionId transId) {
		this.transId = transId;
	}
	
	public TransactionId getTransactionId() {
		return transId;
	}
	
	void setEncoded(byte[] encoded) {
		this.encoded = encoded;
	}
	
	public byte[] getEncoded() {
		return encoded;
	}
	
	void setMessageType(MessageType msgType) {
		this.msgType = msgType;
	}
	
	public MessageType getMessageType() {
		return msgType;
	}
}
