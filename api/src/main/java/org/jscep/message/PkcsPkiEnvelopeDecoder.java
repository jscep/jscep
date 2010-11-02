/*
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.message;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class PkcsPkiEnvelopeDecoder {
	private final PrivateKey priKey;
	
	public PkcsPkiEnvelopeDecoder(PrivateKey priKey) {
		this.priKey = priKey;
	}
	
	public ASN1Encodable decode(EnvelopedData envelopedData) throws IOException {
		// Figure out the type of secret key
		final EncryptedContentInfo contentInfo = envelopedData.getEncryptedContentInfo();
		final AlgorithmIdentifier contentAlg = contentInfo.getContentEncryptionAlgorithm();
		final String cipherName = getCipherName(contentAlg.getObjectId().getId());

		Cipher decryptingCipher;
		AlgorithmParameters params;
		try {
			decryptingCipher = Cipher.getInstance(cipherName + "/CBC/NoPadding");
			params = AlgorithmParameters.getInstance(cipherName);
			DEROctetString paramsString = (DEROctetString) contentAlg.getParameters();
			params.init(paramsString.getEncoded());
		} catch (Exception e) {
			throw new IOException(e);
		}
		
		// Make sure we have a recipientInfo to decrypt the key
		final ASN1Set recipientInfos = envelopedData.getRecipientInfos();
		if (recipientInfos.size() == 0) {
			throw new IOException("Invalid RecipientInfos");
		}
		
		byte[] encryptedContentBytes = contentInfo.getEncryptedContent().getOctets();
		RecipientInfo encodable = RecipientInfo.getInstance(recipientInfos.getObjectAt(0));
		KeyTransRecipientInfo keyTrans = KeyTransRecipientInfo.getInstance(encodable.getInfo());		
		byte[] wrappedKey = keyTrans.getEncryptedKey().getOctets();
		try {
			// Decrypt the secret key
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.UNWRAP_MODE, priKey);
			SecretKey secretKey = (SecretKey) cipher.unwrap(wrappedKey, cipherName, Cipher.SECRET_KEY);
			// Use the secret key to decrypt the content
			decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey, params);
			byte[] contentBytes = decryptingCipher.doFinal(encryptedContentBytes);
			
			return ASN1Object.fromByteArray(contentBytes);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	private String getCipherName(String oid) {
		if (oid.equals("1.3.14.3.2.7")) {
			return "DES";
		} else {
			return "TripleDES";
		}
	}
}
