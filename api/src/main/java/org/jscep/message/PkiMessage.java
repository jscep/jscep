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

import java.util.Collection;
import java.util.HashSet;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

public abstract class PkiMessage<T extends ASN1Encodable> {
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
	
	public Collection<Attribute> getAttributes() {
		final Collection<Attribute> attrs = new HashSet<Attribute>();

		final Attribute transIdAttr = new Attribute(ScepObjectIdentifiers.transId, toSet(transId));
		final Attribute messageTypeAttr = new Attribute(ScepObjectIdentifiers.messageType, toSet(messageType));
		final Attribute senderNonceAttr = new Attribute(ScepObjectIdentifiers.senderNonce, toSet(senderNonce));
		attrs.add(transIdAttr);
		attrs.add(messageTypeAttr);
		attrs.add(senderNonceAttr);
		
		return attrs;
	}
	
	protected ASN1Set toSet(Nonce nonce) {
		return new DERSet(new DEROctetString(nonce.getBytes()));
	}
	
	private ASN1Set toSet(TransactionId transId) {
		return new DERSet(new DERPrintableString(transId.getBytes()));
	}
	
	private ASN1Set toSet(MessageType messageType) {
		return new DERSet(new DERPrintableString(messageType.toString()));
	}
}
