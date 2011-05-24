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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.util.LoggingUtil;


/**
 * This class handles responses to <code>GetCACert</code> requests.
 * 
 * @author David Grant
 */
public class CaCertificateContentHandler implements ScepContentHandler<List<X509Certificate>> {
	private static Logger LOGGER = LoggingUtil.getLogger(CaCertificateContentHandler.class);
	
	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getContent(InputStream in, String mimeType) throws IOException {
		LOGGER.entering(getClass().getName(), "getContent", new Object[] {in, mimeType});
		
		final List<X509Certificate> certs = new ArrayList<X509Certificate>(2);
		final CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			IOException ioe = new IOException(e);
			
			LOGGER.throwing(getClass().getName(), "getContent", ioe);
			throw ioe;
		}

		if (mimeType.equals("application/x-x509-ca-cert")) {
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.1.1.1
			try {

				X509Certificate ca = (X509Certificate) cf.generateCertificate(in);

				// There should only ever be one certificate in this response.
				certs.add(ca);
			} catch (CertificateException ce) {
				IOException ioe = new IOException(ce);
				
				LOGGER.throwing(getClass().getName(), "getContent", ioe);
				throw ioe;
			}
		} else if (mimeType.equals("application/x-x509-ca-ra-cert")) {
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

			CertStore store;
			try {
				byte[] bytes = baos.toByteArray();
				if (bytes.length == 0) {
					throw new IOException("Expected a SignedData object, but response was empty");
				}
				CMSSignedData sd = new CMSSignedData(bytes);

				store = sd.getCertificatesAndCRLs("Collection", (String) null);
			} catch (Exception e) {
				throw new IOException(e);
			}
			
			CertSelector selector = new X509CertSelector();
			try {
				@SuppressWarnings("unchecked")
				Collection<X509Certificate> certsCollection = (Collection<X509Certificate>) store.getCertificates(selector);
				for (X509Certificate cert : certsCollection) {
					certs.add(cert);
				}
			} catch (CertStoreException e) {
				IOException ioe = new IOException(e);
				
				LOGGER.throwing(getClass().getName(), "getContent", ioe);
				throw ioe;
			}
		} else {
			IOException ioe = new IOException("Invalid Content Type");
			
			LOGGER.throwing(getClass().getName(), "getContent", ioe);
			throw ioe;
		}

		LOGGER.exiting(getClass().getName(), "getContent", certs);
		
		return certs;
	}
}
