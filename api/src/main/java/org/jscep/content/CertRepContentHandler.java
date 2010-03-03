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
package org.jscep.content;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.jscep.pkcs7.PkiMessage;
import org.jscep.pkcs7.PkiMessageParser;
import org.jscep.util.LoggingUtil;


/**
 * This class handles responses to <code>PKIRequest</code> requests.
 * 
 * @author David Grant
 */
public class CertRepContentHandler implements SCEPContentHandler<PkiMessage> {
	private static Logger LOGGER = LoggingUtil.getLogger(CertRepContentHandler.class);
	private final KeyPair keyPair;
	
	/**
	 * Constructs a new instance of <code>CertRepContentHandler</code>.
	 * 
	 * @param keyPair the KeyPair used to decode the {@link PkiMessage}.
	 */
	public CertRepContentHandler(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	/**
	 * {@inheritDoc}
	 * @throws IOException 
	 */
	public PkiMessage getContent(InputStream in, String mimeType) throws IOException {
		LOGGER.entering(getClass().getName(), "getContent", new Object[] {in, mimeType});
		
		if (mimeType.equals("application/x-pki-message")) {
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();

			int b;
			while ((b = in.read()) != -1) {
				baos.write(b);
			
			}
			baos.close();
			
			final ContentInfo contentInfo;
			try {
				contentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(baos.toByteArray()));
			} catch (ClassCastException e) {
				throw new IOException(e);
			}

			final PkiMessageParser parser = new PkiMessageParser();
			parser.setPrivateKey(keyPair.getPrivate());
			final PkiMessage msg = parser.parse(contentInfo);
			
			LOGGER.exiting(getClass().getName(), "getContent", msg);
			return msg;
		} else {
			IOException ioe = new IOException("Invalid Content Type");
			
			LOGGER.throwing(getClass().getName(), "getContent", ioe);
			throw ioe;
		}
	}
}
