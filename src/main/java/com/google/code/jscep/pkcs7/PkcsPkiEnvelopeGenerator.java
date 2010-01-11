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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;

import com.google.code.jscep.util.LoggingUtil;

public class PkcsPkiEnvelopeGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private X509Certificate recipient;
	private AlgorithmIdentifier cipher;
	
	public void setRecipient(X509Certificate recipient) {
		this.recipient = recipient;
	}
	
	public void setCipher(AlgorithmIdentifier cipher) {
		this.cipher = cipher;
	}
	
	public PkcsPkiEnvelope generate(ASN1Encodable messageData) throws IOException {
		LOGGER.entering(getClass().getName(), "generate");

		EnvelopedData ed;
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    	gen.addKeyTransRecipient(recipient);
    	CMSProcessable processableData = new CMSProcessableByteArray(messageData.getDEREncoded());
    	CMSEnvelopedData envelopedData;
		try {
//			final X509Name name = new X509Name(recipient.getIssuerDN().getName());
//			final BigInteger serialNumber = recipient.getSerialNumber();
//			final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serialNumber);
//			final RecipientIdentifier rid = new RecipientIdentifier(iasn);
//			final AlgorithmIdentifier keyEncryptionAlgorithm = null;
//			final ASN1OctetString encryptedKey = null;
//			final KeyTransRecipientInfo keyTrans = new KeyTransRecipientInfo(rid, keyEncryptionAlgorithm, encryptedKey);
//			final ASN1Set recipientInfos = new DERSet(keyTrans);
//			
//			EncryptedContentInfo contentInfo = null;
//			ed = new EnvelopedData(null, recipientInfos, contentInfo, null);
			
			// Need BC Provider Here.
			envelopedData = gen.generate(processableData, cipher.getObjectId().getId(), "BC");
		} catch (Exception e) {
			
			IOException ioe = new IOException(e);
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}
    	
    	PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl();
    	envelope.setEncoded(envelopedData.getEncoded());
    	envelope.setMessageData(messageData);
    	
    	LOGGER.exiting(getClass().getName(), "generate", envelope);
		return envelope;
	}
}
