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
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.cms.SignedData;

/**
 * Content handler for GetNextCA requests.
 */
public class NextCaCertificateContentHandler implements
		ScepContentHandler<List<X509Certificate>> {
	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getContent(InputStream in, String mimeType)
			throws IOException {
		if (mimeType.equals(X509_NEXT_CA_CERT)) {
			// TODO: MISSING: GetNextCACert Response
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1
			
			// The response consists of a SignedData PKCS#7 [RFC2315], 
			// signed by the current CA (or RA) signing key.
//			SignedData sd = new SignedData(null);
			return null;
		} else {
			throw new IOException("Invalid Content Type");
		}
	}
}
