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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Hex;


/**
 * Merge with Enveloper.
 */
public class Signer {
	private final static Logger LOGGER = Logger.getLogger(Signer.class.getName());
	private final String digest;
	private final X509Certificate identity;
	private final KeyPair keyPair;
	
	public Signer(X509Certificate identity, KeyPair keyPair, String digest) {
		this.identity = identity;
		this.keyPair = keyPair;
		this.digest = digest;
	}
	
	public byte[] sign(byte[] data, MessageType msgType, TransactionId transId, Nonce senderNonce) throws IOException, GeneralSecurityException, CmsException {
		CMSProcessable envelopedData = new CMSProcessableByteArray(data);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    	
    	List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(identity);
        
        CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
        try {
			gen.addCertificatesAndCRLs(certs);
		} catch (CMSException e) {
			throw new CmsException(e);
		}
		Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>();
		attributes.put(toAttribute(msgType).getAttrType(), toAttribute(msgType));
        attributes.put(toAttribute(transId).getAttrType(), toAttribute(transId));
        attributes.put(toAttribute(senderNonce).getAttrType(), toAttribute(senderNonce));
		AttributeTable table = new AttributeTable(attributes);
        gen.addSigner(keyPair.getPrivate(), identity, digest, table, null);
        
    	CMSSignedData signedData;
		try {
			signedData = gen.generate(envelopedData, true, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	LOGGER.info("SignedData: " + new String(Hex.encode(signedData.getEncoded())));
    	
    	return signedData.getEncoded();
	}
	
	private Attribute toAttribute(MessageType msgType) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType.getOid());
    	DERPrintableString attr = new DERPrintableString(Integer.toString(msgType.getValue()));
    	
        return new Attribute(oid, new DERSet(attr));
	}
	
	private Attribute toAttribute(TransactionId transId) {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId.getOid());
		
        return new Attribute(oid, new DERSet(new DERPrintableString(transId.getBytes())));
	}
	
	 private Attribute toAttribute(Nonce senderNonce) {
    	DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce.getOid());
    	
        return new Attribute(oid, new DERSet(new DEROctetString(senderNonce.getBytes())));
    }
}
