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

package com.google.code.jscep.content;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;

import com.google.code.jscep.pkcs7.DegenerateSignedData;
import com.google.code.jscep.pkcs7.DegenerateSignedDataParser;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class handles responses to <tt>GetNextCACert</tt> requests.
 */
public class NextCaCertificateContentHandler implements ScepContentHandler<List<X509Certificate>> {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.content");
	
	public NextCaCertificateContentHandler(X509Certificate ca) {
//		this.ca = ca;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getContent(InputStream in, String mimeType) throws IOException {
		LOGGER.entering(getClass().getName(), "getContent", new Object[] {in, mimeType});
		
		if (mimeType.equals("application/x-x509-next-ca-cert")) {
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

			// TODO: This must be signed by the current CA.
			// The response consists of a SignedData PKCS#7 [RFC2315], 
			// signed by the current CA (or RA) signing key.
			final List<X509Certificate> certs = new ArrayList<X509Certificate>();
			
			Collection<? extends Certificate> collection;
			try {
				DegenerateSignedDataParser parser = new DegenerateSignedDataParser();
				DegenerateSignedData sd = parser.parse(ASN1Object.fromByteArray(getBytes(in)));
				CertStore store = sd.getCertStore();
				collection = store.getCertificates(new X509CertSelector());
//				CertificateFactory cf = CertificateFactory.getInstance("X.509");
//				collection = cf.generateCertificates(in);
			} catch (CertStoreException e) {
				IOException ioe = new IOException(e);
				LOGGER.throwing(getClass().getName(), "getContent", ioe);
				throw ioe;
			}
			
			for (Certificate cert : collection) {
				certs.add((X509Certificate) cert);
			}

			LOGGER.exiting(getClass().getName(), "getContent", certs);
			return certs;
		} else {
			IOException ioe = new IOException("Invalid Content Type");
			
			LOGGER.throwing(getClass().getName(), "getContent", ioe);
			throw ioe;
		}
	}
	
	private byte[] getBytes(InputStream in) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		int i;
		while ((i = in.read()) != -1) {
			baos.write(i);
		}
		
		return baos.toByteArray();
	}
}
