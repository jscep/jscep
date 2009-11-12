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

package com.google.code.jscep.transaction;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.util.Collection;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.google.code.jscep.RequestPendingException;
import com.google.code.jscep.asn1.MessageType;
import com.google.code.jscep.asn1.PkiStatus;
import com.google.code.jscep.asn1.ScepObjectIdentifiers;

public class CmsResponseParser {
	private final byte[] transId;
	private final byte[] senderNonce;
    private final KeyPair keyPair;
	
	public CmsResponseParser(byte[] transId, byte[] senderNonce, KeyPair keyPair) {
		this.transId = transId;
		this.senderNonce = senderNonce;
		this.keyPair = keyPair;
	}
	
    public CertStore handleResponse(byte[] bytes) throws CmsException, RequestPendingException {
    	CMSSignedData signedData;
		try {
			signedData = new CMSSignedData(bytes);
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        
        if (signers.size() > 1) {
        	throw new CmsException("Too Many SignerInfos");
        }
        SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
        AttributeTable signedAttrs = signerInformation.getSignedAttributes();

        DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId.getOid());
        Attribute transIdAttr = signedAttrs.get(oid);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        if (transId.equals(new DERPrintableString(this.transId)) == false) {
            throw new CmsException("Transaction ID Mismatch: Sent [" + this.transId + "]; Received [" + transId + "]");
        }
        
        oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType.getOid());
        Attribute msgTypeAttribute = signedAttrs.get(oid);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        int msgTypeVal = Integer.parseInt(msgType.getString());
        if (msgTypeVal != MessageType.CertRep.getValue()) {
        	throw new CmsException("Invalid Message Type: " + msgType);
        }
        
//        Attribute senderNoneAttribute = signedAttrs.get(ScepObjectIdentifiers.senderNonce);
//        DEROctetString senderNonce = (DEROctetString) senderNoneAttribute.getAttrValues().getObjectAt(0);
        
        oid = new DERObjectIdentifier(ScepObjectIdentifiers.recipientNonce.getOid());
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString recipientNonce = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        if (recipientNonce.equals(new DEROctetString(this.senderNonce)) == false) {
        	throw new CmsException("Sender Nonce Mismatch.  Sent [" + this.senderNonce + "]; Received [" + recipientNonce + "]");
        }
        
        oid = new DERObjectIdentifier(ScepObjectIdentifiers.pkiStatus.getOid());
        Attribute pkiStatusAttribute = signedAttrs.get(oid);
        DERPrintableString pkiStatus = (DERPrintableString) pkiStatusAttribute.getAttrValues().getObjectAt(0);
        
        if (pkiStatus.equals(PkiStatus.FAILURE)) {
//        	oid = new DERObjectIdentifier(ScepObjectIdentifiers.failInfo.getOid());
//        	Attribute failInfoAttribute = signedAttrs.get(oid);
//        	DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
        	
        	return null;
        } else if (pkiStatus.equals(PkiStatus.PENDING)) {
        	// TODO How can we handle pending results?
        	throw new RequestPendingException();
        }
        
        try {
        	CMSProcessable signedContent = signedData.getSignedContent();
        	CMSEnvelopedData envelopedData = new CMSEnvelopedData((byte[]) signedContent.getContent());
        	RecipientInformationStore recipientStore = envelopedData.getRecipientInfos();
        	RecipientInformation recipient = (RecipientInformation) recipientStore.getRecipients().iterator().next();
        	byte[] content = recipient.getContent(keyPair.getPrivate(), "BC");
        	CMSSignedData contentData = new CMSSignedData(content);
        	
			return contentData.getCertificatesAndCRLs("Collection", "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		} catch (GeneralSecurityException e) {
			throw new CmsException(e);
		}
    }
}
