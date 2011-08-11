/*
 * Copyright (c) 2009-2010 David Grant
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
package org.jscep.content;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.Collection;
import java.util.Collections;


/**
 * This class handles responses to <code>GetCACert</code> requests.
 * 
 * @author David Grant
 */
public class CaCertificateContentHandler implements ScepContentHandler<CertStore> {
	private static Logger LOGGER = LoggingUtil.getLogger(CaCertificateContentHandler.class);
	
	/**
	 * {@inheritDoc}
	 */
	public CertStore getContent(InputStream in, String mimeType) throws IOException {
		final CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
		} catch (CertificateException e) {
			IOException ioe = new IOException(e);
			
			LOGGER.error("getContent", ioe);
			throw ioe;
		}

		if (mimeType.startsWith("application/x-x509-ca-cert")) {
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.1.1.1
			try {

				X509Certificate ca = (X509Certificate) cf.generateCertificate(in);
                Collection<X509Certificate> caSet = Collections.singleton(ca);
                CertStoreParameters storeParams = new CollectionCertStoreParameters(caSet);

                return CertStore.getInstance("Collection", storeParams);
			} catch (GeneralSecurityException e) {
				IOException ioe = new IOException(e);
				
				LOGGER.error("getContent", ioe);
				throw ioe;
			}
		} else if (mimeType.startsWith("application/x-x509-ca-ra-cert")) {
			// If an RA is in use, a certificates-only PKCS#7 SignedData
			// with a certificate chain consisting of both RA and CA certificates is
			// returned.
			// It should be in the order:
			// [0] RA
			// [1] CA
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			int b;
			while ((b = in.read()) != -1) {
				baos.write(b);
			}
			
			// This area needs testing!

			try {
				byte[] bytes = baos.toByteArray();
				if (bytes.length == 0) {
					throw new IOException("Expected a SignedData object, but response was empty");
				}
				CMSSignedData sd = new CMSSignedData(bytes);

				return sd.getCertificatesAndCRLs("Collection", (String) null);
			} catch (GeneralSecurityException e) {
				throw new IOException(e);
			} catch (CMSException e) {
                throw new IOException(e);
            }
        } else {
			IOException ioe = new IOException("Invalid Content Type");
			
			LOGGER.error("getContent", ioe);
			throw ioe;
		}
	}
}
