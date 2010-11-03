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
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

public class PkiResponse<T extends ASN1Encodable> extends PkiMessage<T> {
	private final Nonce recipientNonce;
	private final PkiStatus pkiStatus;
	private final FailInfo failInfo;
	
	public PkiResponse(TransactionId transId, MessageType messageType, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus, T messageData) {
		// SUCCESS
		super(transId, messageType, senderNonce, messageData);
	
		this.recipientNonce = recipientNonce;
		this.pkiStatus = pkiStatus;
		this.failInfo = null;
	}
	
	public PkiResponse(TransactionId transId, MessageType messageType, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus, FailInfo failInfo) {
		// FAILURE
		super(transId, messageType, senderNonce, null);
	
		this.recipientNonce = recipientNonce;
		this.pkiStatus = pkiStatus;
		this.failInfo = failInfo;
	}
	
	public PkiResponse(TransactionId transId, MessageType messageType, Nonce senderNonce, Nonce recipientNonce, PkiStatus pkiStatus) {
		// PENDING
		super(transId, messageType, senderNonce, null);
	
		this.recipientNonce = recipientNonce;
		this.pkiStatus = pkiStatus;
		this.failInfo = null;
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
	
	@Override
	public Collection<Attribute> getAttributes() {
		final Collection<Attribute> attrs = new HashSet<Attribute>();
		
		final Attribute pkiStatusAttr = new Attribute(ScepObjectIdentifiers.pkiStatus, toSet(pkiStatus));
		final Attribute recipientNonceAttr = new Attribute(ScepObjectIdentifiers.recipientNonce, toSet(recipientNonce));
		attrs.add(pkiStatusAttr);
		attrs.add(recipientNonceAttr);
		
		if (pkiStatus == PkiStatus.FAILURE) {
			final Attribute failInfoAttr = new Attribute(ScepObjectIdentifiers.failInfo, toSet(failInfo));
			attrs.add(failInfoAttr);
		}
		
		attrs.addAll(super.getAttributes());
		
		return attrs;
	}

	private ASN1Set toSet(FailInfo failInfo) {
		return new DERSet(new DERPrintableString(failInfo.toString()));
	}

	private ASN1Set toSet(PkiStatus pkiStatus) {
		return new DERSet(new DERPrintableString(pkiStatus.toString()));
	}
}
