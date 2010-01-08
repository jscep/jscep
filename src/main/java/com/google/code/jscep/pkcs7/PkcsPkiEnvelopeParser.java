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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

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
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

import com.google.code.jscep.util.LoggingUtil;

public class PkcsPkiEnvelopeParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private final PrivateKey privKey;
	
	public PkcsPkiEnvelopeParser(PrivateKey keyPair) {
		this.privKey = keyPair;
	}
	
	@SuppressWarnings("unchecked")
	public PkcsPkiEnvelope parse(byte[] envelopeBytes) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");
		
		EnvelopedData cmsEd;
		CMSEnvelopedData ed;
		try {
			ASN1Object enc = ASN1Object.fromByteArray(envelopeBytes);
			ContentInfo info = ContentInfo.getInstance(enc);
			assert(info.getContentType().equals(CMSObjectIdentifiers.envelopedData));
			ASN1Sequence seq = (ASN1Sequence) info.getContent();
			cmsEd = new EnvelopedData((ASN1Sequence) seq);
			ed = new CMSEnvelopedData(envelopeBytes);
		} catch (CMSException e) {
			
			IOException ioe = new IOException(e);
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}
		
		EncryptedContentInfo eci = cmsEd.getEncryptedContentInfo();
		ASN1OctetString ec = eci.getEncryptedContent();
		AlgorithmIdentifier algId = eci.getContentEncryptionAlgorithm();
		
		ASN1Set recipientInfoSet = cmsEd.getRecipientInfos();
		Enumeration<?> riEnum = recipientInfoSet.getObjects();
		while (riEnum.hasMoreElements()) {
			ASN1Sequence seq = (ASN1Sequence) riEnum.nextElement();
			RecipientInfo ri = new RecipientInfo((DERObject) seq);
			assert(ri.getInfo() instanceof KeyTransRecipientInfo);
			KeyTransRecipientInfo info = (KeyTransRecipientInfo) ri.getInfo();
			ASN1OctetString key = info.getEncryptedKey();
			AlgorithmIdentifier alg = info.getKeyEncryptionAlgorithm();
			byte[] keyBytes;
			try {
				Cipher cipher = Cipher.getInstance(alg.getObjectId().getId());
				cipher.init(Cipher.DECRYPT_MODE, privKey);
				keyBytes = cipher.doFinal(key.getOctets());
				System.out.println(keyBytes);
				
				Cipher msgCipher = Cipher.getInstance(algId.getObjectId().getId());
				System.out.println(algId.getObjectId().getId());
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
				DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
				SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
				System.out.println(secretKey);
				msgCipher.init(Cipher.DECRYPT_MODE, secretKey, (AlgorithmParameters) null);
				byte[] content = msgCipher.doFinal(ec.getOctets());
				System.out.println(content);
			} catch (GeneralSecurityException e) {
				throw new IOException(e);
			}

			System.out.println(alg.getObjectId());
			System.out.println(info);
		}
		
		final RecipientInformationStore recipientStore = ed.getRecipientInfos();
		final Collection<RecipientInformation> recipientInfos = recipientStore.getRecipients();
    	final RecipientInformation recipient = recipientInfos.iterator().next();
    	
    	byte[] msgData;
		try {
			msgData = recipient.getContent(privKey, "BC");
		} catch (Exception e) {
			
			IOException ioe = new IOException(e);
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}

    	final PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl();
    	envelope.setMessageData(ASN1Object.fromByteArray(msgData));
    	envelope.setEncoded(envelopeBytes);
    	
    	LOGGER.exiting(getClass().getName(), "parse", envelope);
		return envelope;
	}
}
