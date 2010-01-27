/*
 * Copyright (c) 2009-2010 David Grant
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
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.google.code.jscep.asn1.SCEPObjectIdentifiers;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

/**
 * This interface represents the <tt>SCEP</tt> <tt>pkiMessage</tt>.
 *
 * @author davidjgrant1978
 */
public class PkiMessage {
	private PkcsPkiEnvelope pkcsPkiEnvelope;
	private final SignerInfo signerInfo;
	private final ContentInfo contentInfo;
	private final SignedData signedData;
	
	PkiMessage(ContentInfo contentInfo) {
		this.contentInfo = contentInfo;
		this.signedData = SignedData.getInstance(contentInfo.getContent());
		this.signerInfo = getSignerSet(signedData).iterator().next();
	}
	
	private Set<SignerInfo> getSignerSet(SignedData signedData) {
		final Set<SignerInfo> set = new HashSet<SignerInfo>();
		final Enumeration<?> signerInfos = signedData.getSignerInfos().getObjects();
		
		while (signerInfos.hasMoreElements()) {
			set.add(SignerInfo.getInstance(signerInfos.nextElement()));
		}
		
		return set;
	}
	
	public boolean isRequest() {
		return getPkiStatus() == null;
	}
	
	private AttributeTable getAttributeTable() {
		return new AttributeTable(signerInfo.getAuthenticatedAttributes());
	}

	void setPkcsPkiEnvelope(PkcsPkiEnvelope envelope) {
		this.pkcsPkiEnvelope = envelope;
	}
	
	public PkcsPkiEnvelope getPkcsPkiEnvelope() {
		return pkcsPkiEnvelope;
	}
	
	public FailInfo getFailInfo() {
		final Attribute attr = getAttributeTable().get(SCEPObjectIdentifiers.failInfo);
		if (attr == null) {
			return null;
		}
		final DERPrintableString failInfo = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return FailInfo.valueOf(Integer.parseInt(failInfo.getString()));
	}
	
	public PkiStatus getPkiStatus() {
		final Attribute attr = getAttributeTable().get(SCEPObjectIdentifiers.pkiStatus);
		if (attr == null) {
			return null;
		}
		final DERPrintableString pkiStatus = (DERPrintableString) attr.getAttrValues().getObjectAt(0);

		return PkiStatus.valueOf(Integer.parseInt(pkiStatus.toString()));
	}
	
	private Nonce getNonce(DERObjectIdentifier oid) {
		final Attribute attr = getAttributeTable().get(oid);
		if (attr == null) {
			return null;
		}
		final DEROctetString nonce = (DEROctetString) attr.getAttrValues().getObjectAt(0);

		return new Nonce(nonce.getOctets());
	}
	
	public Nonce getRecipientNonce() {
		return getNonce(SCEPObjectIdentifiers.recipientNonce);
	}
	
	public Nonce getSenderNonce() {
		return getNonce(SCEPObjectIdentifiers.senderNonce);
	}
	
	public TransactionId getTransactionId() {
		final Attribute attr = getAttributeTable().get(SCEPObjectIdentifiers.transId);
		DERPrintableString transId = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return new TransactionId(transId.getOctets());
	}
	
	public byte[] getEncoded() throws IOException {
		return contentInfo.getEncoded();
	}
	
	public MessageType getMessageType() {
		final Attribute attr = getAttributeTable().get(SCEPObjectIdentifiers.messageType);
		final DERPrintableString msgType = (DERPrintableString) attr.getAttrValues().getObjectAt(0);
		
		return MessageType.valueOf(Integer.parseInt(msgType.getString()));
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (getPkiStatus() == null) {
			sb.append("pkiMessage (request) [\n");
		} else {
			sb.append("pkiMessage (response) [\n");
		}
		sb.append("\tcontentType: " + contentInfo.getContentType() + "\n");
		sb.append("\ttransactionId: " + getTransactionId() + "\n");
		sb.append("\tmessageType: " + getMessageType() + "\n");
		if (getPkiStatus() != null) {
			sb.append("\tpkiStatus: " + getPkiStatus() + "\n");
		}
		if (getFailInfo() != null) {
			sb.append("\tfailInfo: " + getFailInfo() + "\n");
		}
		sb.append("\tsenderNonce: " + getSenderNonce() + "\n");
		if (getRecipientNonce() != null) {
			sb.append("\trecipientNonce: " + getRecipientNonce() + "\n");
		}
		sb.append("\tpkcsPkiEnvelope: " + pkcsPkiEnvelope.toString().replaceAll("\n", "\n\t") + "\n");
		sb.append("]");
		
		return sb.toString();
	}
	
	@Override
	public boolean equals(Object o) {
		if (o instanceof PkiMessage == false) {
			return false;
		}
		final PkiMessage other = (PkiMessage) o;
		
		try {
			return Arrays.equals(getEncoded(), other.getEncoded());
		} catch (IOException e) {
			return false;
		}
	}
}
