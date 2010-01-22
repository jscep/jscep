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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.google.code.jscep.util.LoggingUtil;

public class PkcsPkiEnvelopeParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private final PrivateKey privKey;
	
	public PkcsPkiEnvelopeParser(PrivateKey keyPair) {
		this.privKey = keyPair;
	}
	
	public PkcsPkiEnvelope parse(byte[] envelopeBytes) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");
		
		ASN1Object enc = ASN1Object.fromByteArray(envelopeBytes);
		ContentInfo envInfo = ContentInfo.getInstance(enc);
		assert(envInfo.getContentType().equals(CMSObjectIdentifiers.envelopedData));
		EnvelopedData cmsEd = new EnvelopedData((ASN1Sequence) envInfo.getContent());
		// 3.1.2 version MUST be 0
		assert(cmsEd.getVersion().getValue().equals(BigInteger.ZERO));
		
		final EncryptedContentInfo eci = cmsEd.getEncryptedContentInfo();
		
		// 3.1.2 contentType in encryptedContentInfo MUST be data as defined in PKCS#7 
		assert(eci.getContentType().equals(CMSObjectIdentifiers.data));
		final ASN1OctetString ec = eci.getEncryptedContent();
		final AlgorithmIdentifier algId = eci.getContentEncryptionAlgorithm();
		
		ASN1Set recipientInfoSet = cmsEd.getRecipientInfos();
		Enumeration<?> riEnum = recipientInfoSet.getObjects();
		ContentInfo ci = null;
		while (riEnum.hasMoreElements()) {
			final ASN1Sequence seq = (ASN1Sequence) riEnum.nextElement();
			final RecipientInfo ri = new RecipientInfo((DERObject) seq);
			assert(ri.getInfo() instanceof KeyTransRecipientInfo);
			
			final KeyTransRecipientInfo keyTransInfo = (KeyTransRecipientInfo) ri.getInfo();
			final ASN1OctetString key = keyTransInfo.getEncryptedKey();
			try {
				// TODO: Hardcoded Algorithm
				final Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.UNWRAP_MODE, privKey);
				// TODO: Hardcoded Algorithm
				final Key secretKey = cipher.unwrap(key.getOctets(), "DES", Cipher.SECRET_KEY);
				
				final ASN1Object params = (ASN1Object) algId.getParameters();
				AlgorithmParameters algParams = AlgorithmParameters.getInstance("DES");
				algParams.init(params.getEncoded());
				
				// TODO: Hardcoded Algorithm
				final Cipher msgCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
				msgCipher.init(Cipher.DECRYPT_MODE, secretKey, algParams);
				final byte[] content = msgCipher.doFinal(ec.getOctets());
				
				ci = ContentInfo.getInstance(ASN1Object.fromByteArray(content));
			} catch (GeneralSecurityException e) {
				throw new IOException(e);
			}
		}

    	final PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl(envInfo);
    	envelope.setMessageData(ci);
    	
    	LOGGER.exiting(getClass().getName(), "parse", envelope);
		return envelope;
	}
}
