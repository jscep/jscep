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

package com.google.code.jscep.content;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import com.google.code.jscep.util.LoggingUtil;

/**
 * This class handles responses to <tt>GetNextCACert</tt> requests.
 */
public class NextCaCertificateContentHandler implements
		ScepContentHandler<List<X509Certificate>> {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.content");
	
	public NextCaCertificateContentHandler(X509Certificate ca) {
//		this.ca = ca;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getContent(InputStream in, String mimeType)
			throws IOException {
		if (mimeType.equals("application/x-x509-next-ca-cert")) {
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

			// TODO: This must be signed by the current CA.
			// The response consists of a SignedData PKCS#7 [RFC2315], 
			// signed by the current CA (or RA) signing key.
			final List<X509Certificate> certs = new ArrayList<X509Certificate>();
			CertificateFactory cf;
			try {
				cf = CertificateFactory.getInstance("X.509");
			} catch (CertificateException e) {
				throw new IOException(e);
			}
			Collection<? extends Certificate> collection;
			try {
				collection = cf.generateCertificates(in);
			} catch (CertificateException e) {
				throw new IOException(e);
			}
			for (Certificate cert : collection) {
				certs.add((X509Certificate) cert);
			}

			return certs;
		} else {
			throw new IOException("Invalid Content Type");
		}
	}
}
