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

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Hex;

import com.google.code.jscep.ScepException;
import com.google.code.jscep.asn1.MessageType;
import com.google.code.jscep.asn1.PkiStatus;
import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import com.google.code.jscep.request.PkiOperation;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.transport.Transport;

/**
 * Please refactor me.  I have far too many responsibilities.
 */
public class Transaction {
    private static final AtomicLong COUNTER = new AtomicLong();
    private final DERPrintableString transId;
    private DEROctetString senderNonce;
    private int reason;
    private final KeyPair keyPair;
    private List<X509CRL> crls;
    private List<X509Certificate> certs;
    private final Transport transport;
    private final Enveloper enveloper;
    private final Signer signer;
    
    protected Transaction(Transport transport, KeyPair keyPair, Enveloper enveloper, Signer signer) {
    	this.transport = transport;
    	this.keyPair = keyPair;
        this.transId = generateTransactionId();
        this.senderNonce = generateSenderNonce();
        this.enveloper = enveloper;
        this.signer = signer;
    }
    
    private DEROctetString generateSenderNonce() {
    	return new DEROctetString(NonceFactory.nextNonce().getBytes());
    }
    
    private DERPrintableString generateTransactionId() {
    	if (keyPair == null) {
    		return new DERPrintableString(Long.toHexString(COUNTER.getAndIncrement()).getBytes());
    	} else {
	    	MessageDigest digest = null;
	        try {
	            digest = MessageDigest.getInstance("MD5");
	        } catch (NoSuchAlgorithmException e) {
	            throw new RuntimeException(e);
	        }
	        return new DERPrintableString(Hex.encode(digest.digest(keyPair.getPublic().getEncoded())));
    	}
    }
    
    public int getFailureReason() {
    	return reason;
    }

    public CertStore performOperation(PkiOperation operation) throws MalformedURLException, IOException, ScepException {
    	try {
    		CMSEnvelopedData enveloped = enveloper.envelope(operation);
    		CMSProcessable envelopedData = new CMSProcessableByteArray(enveloped.getEncoded());
	
	        Attribute msgType = getMessageTypeAttribute(operation);
	        Attribute transId = getTransactionIdAttribute();
	        Attribute senderNonce = getSenderNonceAttribute();
	
	        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>();
	        attributes.put(msgType.getAttrType(), msgType);
	        attributes.put(transId.getAttrType(), transId);
	        attributes.put(senderNonce.getAttrType(), senderNonce);
	        AttributeTable table = new AttributeTable(attributes);
	
	        CMSSignedData signedData = signer.sign(envelopedData, table);
	        PkiRequest request = new PkiRequest(signedData);
	        CMSSignedData response = (CMSSignedData) transport.sendMessage(request);
    	
	        return handleResponse(response);
    	} catch (CMSException e) {
    		throw new ScepException(e);
    	} catch (GeneralSecurityException e) {
    		throw new ScepException(e);
    	}
    }
    
    private Attribute getMessageTypeAttribute(PkiOperation operation) {
        return new Attribute(ScepObjectIdentifiers.messageType, new DERSet(operation.getMessageType()));
    }
    

    private Attribute getTransactionIdAttribute() {
        return new Attribute(ScepObjectIdentifiers.transId, new DERSet(transId));
    }

    private Attribute getSenderNonceAttribute() {
        return new Attribute(ScepObjectIdentifiers.senderNonce, new DERSet(senderNonce));
    }
    
    public CertStore handleResponse(CMSSignedData signedData) throws ScepException {
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        
        if (signers.size() > 1) {
        	throw new ScepException("Too Many SignerInfos");
        }
        SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
        AttributeTable signedAttrs = signerInformation.getSignedAttributes();

        Attribute transIdAttr = signedAttrs.get(ScepObjectIdentifiers.transId);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        if (transId.equals(this.transId) == false) {
            throw new ScepException("Transaction ID Mismatch: Sent [" + this.transId + "]; Received [" + transId + "]");
        }
        
        Attribute msgTypeAttribute = signedAttrs.get(ScepObjectIdentifiers.messageType);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        if (msgType.equals(MessageType.CertRep) == false) {
        	throw new ScepException("Invalid Message Type: " + msgType);
        }
        
//        Attribute senderNoneAttribute = signedAttrs.get(ScepObjectIdentifiers.senderNonce);
//        DEROctetString senderNonce = (DEROctetString) senderNoneAttribute.getAttrValues().getObjectAt(0);
        
        Attribute recipientNonceAttribute = signedAttrs.get(ScepObjectIdentifiers.recipientNonce);
        DEROctetString recipientNonce = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        if (recipientNonce.equals(this.senderNonce) == false) {
        	throw new ScepException("Sender Nonce Mismatch.  Sent [" + this.senderNonce + "]; Received [" + recipientNonce + "]");
        }
        
        Attribute pkiStatusAttribute = signedAttrs.get(ScepObjectIdentifiers.pkiStatus);
        DERPrintableString pkiStatus = (DERPrintableString) pkiStatusAttribute.getAttrValues().getObjectAt(0);
        
        if (pkiStatus.equals(PkiStatus.FAILURE)) {
        	
        	Attribute failInfoAttribute = signedAttrs.get(ScepObjectIdentifiers.failInfo);
        	DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
        	
        	// Throw Exceptions Here
        	reason = Integer.parseInt(failInfo.toString());
        	return null;
        } else if (pkiStatus.equals(PkiStatus.PENDING)) {
        	return null;
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
			throw new ScepException(e);
		} catch (GeneralSecurityException e) {
			throw new ScepException(e);
		}
    }
    
    public List<X509CRL> getCRLs() {
    	return crls; 
    }
    
    public List<X509Certificate> getCertificates() {
    	return certs;
    }
}
