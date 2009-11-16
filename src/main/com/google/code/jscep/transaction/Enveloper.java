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
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.util.encoders.Hex;

import com.google.code.jscep.util.HexUtil;

/**
 * Merge with Signer.
 */
public class Enveloper {
	private final static Logger LOGGER = Logger.getLogger(Enveloper.class.getName());
	private final String cipher;
	private final X509Certificate ca;
	
	public Enveloper(X509Certificate ca, String cipher) {
		this.ca = ca;
		this.cipher = cipher;
	}
	
	public byte[] envelope(byte[] messageData) throws IOException, GeneralSecurityException, CmsException {
		// TODO: BC Dependency
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    	gen.addKeyTransRecipient(ca);
    	CMSProcessable processableData = new CMSProcessableByteArray(messageData);
    	CMSEnvelopedData envelopedData;
		try {
			envelopedData = gen.generate(processableData, cipher, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	LOGGER.info("OUTGOING EnvelopedData:\n" + HexUtil.formatHex(Hex.encode(envelopedData.getEncoded())));
    	return envelopedData.getEncoded();
	}
}
