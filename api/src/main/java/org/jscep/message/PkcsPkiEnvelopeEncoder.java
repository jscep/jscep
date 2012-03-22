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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cms.*;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

public class PkcsPkiEnvelopeEncoder {
    private static Logger LOGGER = LoggingUtil.getLogger(PkcsPkiEnvelopeEncoder.class);
	private final X509Certificate recipient;
	
	public PkcsPkiEnvelopeEncoder(X509Certificate recipient) {
		this.recipient = recipient;
	}
	
	public CMSEnvelopedData encode(ASN1Encodable messageData) throws IOException {
        LOGGER.debug("Encrypting message: {}", messageData.getDEREncoded());
		CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
		
		byte[] payload;
		if (messageData instanceof DEROctetString) {
			DEROctetString oct = (DEROctetString) messageData;
			payload = oct.getOctets();
		} else {
			payload = messageData.getEncoded();
		}

		CMSProcessable envelopable = new CMSProcessableByteArray(payload);
		edGenerator.addKeyTransRecipient(recipient);
        LOGGER.debug("Encrypting session key using key belonging to '{}'", recipient.getSubjectDN());
		
		try {
			Provider[] providers = Security.getProviders("KeyGenerator.DESEDE");
			if (providers.length > 0) {
                LOGGER.debug("Using '{}' for DESede key generation", providers[0]);
				CMSEnvelopedData data = edGenerator.generate(envelopable, CMSEnvelopedGenerator.DES_EDE3_CBC, providers[0]);
                LOGGER.debug("Encrypted to: {}", data.getEncoded());
                return data;
			} else {
				throw new IOException("No Provider for DESede");
			}
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
