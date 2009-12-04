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

package com.google.code.jscep.response;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.google.code.jscep.transaction.CmsException;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;
import com.google.code.jscep.util.HexUtil;

/**
 * Implementation of {@link CertRep} that uses Bouncy Castle.
 */
public class CertRepImpl extends CertRep {
	private final static Logger LOGGER = Logger.getLogger(CertRepImpl.class.getName());
	private TransactionId transId;
	private PkiStatus pkiStatus;
	private Nonce recipientNonce;
	private Nonce senderNonce;
	private PkcsPkiEnvelope pkcsPkiEnvelope;
	private FailInfo failInfo;
	private final AttributeTable signedAttrs;
	
	public CertRepImpl(KeyPair keyPair, byte[] bytes) throws CmsException {
		LOGGER.info("INCOMING SignedData:\n" + HexUtil.format(bytes));
		CMSSignedData signedData;
		try {
			signedData = new CMSSignedData(bytes);
		} catch (CMSException e) {
			throw new CmsException();
		}
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        
        if (signers.size() > 1) {
        	throw new CmsException("Too Many SignerInfos");
        }
        
        SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
        signedAttrs = signerInformation.getSignedAttributes();

        transId = extractTransactionId();
        recipientNonce = extractRecipientNonce();
        senderNonce = extractSenderNonce();
        pkiStatus = extractStatus();
        
        
        MessageType msgType = extractMessageType();
        
        if (msgType.equals(MessageType.CertRep) == false) {
        	throw new RuntimeException("Invalid Message Type: " + msgType);
        }
        
        if (pkiStatus.equals(PkiStatus.FAILURE)) {
        	failInfo = extractFailInfo();
        } else {
	        CMSProcessable signedContent = signedData.getSignedContent();
			byte[] ed = (byte[]) signedContent.getContent();
			pkcsPkiEnvelope = PkcsPkiEnvelope.getInstance(keyPair, ed);
        }
	}
	
	public FailInfo getFailInfo() {
		return failInfo;
	}
	
	public PkiStatus getStatus() {
		return pkiStatus;
	}
	
	public Nonce getRecipientNonce() {
		return recipientNonce;
	}
	
	public Nonce getSenderNonce() {
		return senderNonce;
	}
	
	public TransactionId getTransactionId() {
		return transId;
	}
	
	public CertStore getCertStore() throws NoSuchProviderException, NoSuchAlgorithmException, CmsException {
		return pkcsPkiEnvelope.getCertStore();
	}
	
	private TransactionId extractTransactionId() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId.getOid());
        Attribute transIdAttr = signedAttrs.get(oid);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        
        return new TransactionId(transId.getOctets());
	}

	private FailInfo extractFailInfo() {
		DERObjectIdentifier oid;
		oid = new DERObjectIdentifier(ScepObjectIdentifiers.failInfo.getOid());
		Attribute failInfoAttribute = signedAttrs.get(oid);
		DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
		
		return FailInfo.valueOf(Integer.parseInt(failInfo.getString()));
	}

	private Nonce extractRecipientNonce() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.recipientNonce.getOid());
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}
	
	private Nonce extractSenderNonce() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce.getOid());
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}

	private PkiStatus extractStatus() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.pkiStatus.getOid());
        Attribute attr = signedAttrs.get(oid);
        DERPrintableString pkiStatus = (DERPrintableString) attr.getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.parseInt(pkiStatus.toString()));
	}
	
	private MessageType extractMessageType() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType.getOid());
        Attribute msgTypeAttribute = signedAttrs.get(oid);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        
        return MessageType.valueOf(Integer.parseInt(msgType.getString()));
	}
}
