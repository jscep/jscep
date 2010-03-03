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
package org.jscep.pkcs7;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.jscep.util.AlgorithmDictionary;
import org.jscep.util.LoggingUtil;


/**
 * This class is used for parsing SCEP <code>pkcsPKIEnvelope</code> structures.
 * <p>
 * The <code>pkcsPKIEnvelope</code> is a {@link EnvelopedData} with a 
 * {@link MessageData messageData} content.  This class will decrypt the provided
 * {@link ContentInfo}.
 * 
 * @author David Grant
 */
public class PkcsPkiEnvelopeParser {
	private static Logger LOGGER = LoggingUtil.getLogger(PkcsPkiEnvelopeParser.class);
	private final PrivateKey privKey;
	
	/**
	 * Creates a new instance of this class, using the provided PrivateKey
	 * for decryption operations.
	 * 
	 * @param privKey the key to use for decryption.
	 */
	public PkcsPkiEnvelopeParser(PrivateKey privKey) {
		this.privKey = privKey;
	}
	
	/**
	 * Parses the provided {@link EnvelopedData}. 
	 * 
	 * @param envelopedData the data to parse.
	 * @return the parsed pkcsPkiEnvelope.
	 * @throws IOException if any I/O error occurs.
	 */
	public PkcsPkiEnvelope parse(EnvelopedData envelopedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", envelopedData);

		final EncryptedContentInfo encryptedContentInfo = envelopedData.getEncryptedContentInfo();
		final DERInteger version = envelopedData.getVersion();
		final DERObjectIdentifier contentType = encryptedContentInfo.getContentType();
		final ASN1OctetString encryptedContent = encryptedContentInfo.getEncryptedContent();
		final AlgorithmIdentifier contentEncryptionAlgorithm = encryptedContentInfo.getContentEncryptionAlgorithm();
		
		// 3.1.2 version MUST be 0
		if (version.getValue().equals(BigInteger.ZERO) == false) {
			LOGGER.warning("EnvelopedData version MUST be 0");
		}
		// 3.1.2 contentType in encryptedContentInfo MUST be data as defined in PKCS#7 
		if (contentType.equals(CMSObjectIdentifiers.data) == false) {
			LOGGER.warning("contentType in encryptedContentInfo MUST be data.");
		}
		
		final String secretKeyAlg = AlgorithmDictionary.fromTransformation(AlgorithmDictionary.lookup(contentEncryptionAlgorithm));
		
		final ASN1Set recipientInfos = envelopedData.getRecipientInfos();
		ASN1Encodable msgData = null;
		for (int i = 0; i < recipientInfos.size(); i++) {
			final KeyTransRecipientInfo recipientInfo = KeyTransRecipientInfo.getInstance(recipientInfos.getObjectAt(i));
			final ASN1OctetString encryptedKey = recipientInfo.getEncryptedKey();
			
			try {
				final Cipher cipher = Cipher.getInstance(AlgorithmDictionary.lookup(recipientInfo.getKeyEncryptionAlgorithm()));
				cipher.init(Cipher.UNWRAP_MODE, privKey);
				final Key secretKey = cipher.unwrap(encryptedKey.getOctets(), secretKeyAlg, Cipher.SECRET_KEY);
				
				final ASN1Object params = (ASN1Object) contentEncryptionAlgorithm.getParameters();
				AlgorithmParameters algParams = AlgorithmParameters.getInstance(secretKeyAlg);
				algParams.init(params.getEncoded());
				
				final Cipher msgCipher = Cipher.getInstance(AlgorithmDictionary.lookup(contentEncryptionAlgorithm));
				msgCipher.init(Cipher.DECRYPT_MODE, secretKey, algParams);
				final byte[] content = msgCipher.doFinal(encryptedContent.getOctets());
				
				msgData = ASN1Object.fromByteArray(content);
			} catch (GeneralSecurityException e) {
				throw new IOException(e);
			}
		}

    	final PkcsPkiEnvelope envelope = new PkcsPkiEnvelope(envelopedData);
    	envelope.setMessageData(MessageData.getInstance(msgData));
    	
    	LOGGER.exiting(getClass().getName(), "parse", envelope);
		return envelope;
	}
}
