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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;

/**
 * Implementation of {@link PkiMessage} that uses Bouncy Castle.
 */
public class PkiMessageImpl extends ContentInfo implements PkiMessage {
	private Nonce recipientNonce;
	private Nonce senderNonce;
	private FailInfo failInfo;
	private MessageType msgType;
	
	PkiMessageImpl(SignedData data) {
		super(CMSObjectIdentifiers.signedData, data);
	}
	
	public PkcsPkiEnvelope getPkcsPkiEnvelope() throws IOException {
		final EnvelopedData data = (EnvelopedData) getContent().getEncapContentInfo().getContent();
		
		return new PkcsPkiEnvelopeImpl(data);
	}
	
	public FailInfo getFailInfo() {
		return failInfo;
	}
	
	public PkiStatus getStatus() {
		final Attribute attr = getAttributeTable().get(ScepObjectIdentifiers.pkiStatus);
		final DERPrintableString attrValue = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return PkiStatus.valueOf(Integer.parseInt(attrValue.toString()));
	}
	
	public Nonce getRecipientNonce() {
		return recipientNonce;
	}
	
	public Nonce getSenderNonce() {
		return senderNonce;
	}
	
	public TransactionId getTransactionId() {
		final Attribute attr = getAttributeTable().get(ScepObjectIdentifiers.transId);
		final DERPrintableString attrValue = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return new TransactionId(attrValue.getOctets());
	}
	
	public MessageType getMessageType() {
		return msgType;
	}
	
	private SignerInfo getSignerInfo() {
		return new SignerInfo((ASN1Sequence) getContent().getSignerInfos().getObjectAt(0));
	}
	
	private AttributeTable getAttributeTable() {
		return new AttributeTable(getSignerInfo().getAuthenticatedAttributes());
	}
	
	public SignedData getContent() {
		return (SignedData) super.getContent();
	}
}
