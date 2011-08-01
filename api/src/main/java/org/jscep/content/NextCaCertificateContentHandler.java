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
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.pkcs7.SignedDataUtil;

/**
 * This class handles responses to <code>GetNextCACert</code> requests.
 * 
 * @author David Grant
 */
public class NextCaCertificateContentHandler implements ScepContentHandler<List<X509Certificate>> {
	private final X509Certificate issuer;
	
	public NextCaCertificateContentHandler(X509Certificate issuer) {
		this.issuer = issuer;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getContent(InputStream in, String mimeType) throws IOException {
		if (mimeType.startsWith("application/x-x509-next-ca-cert")) {
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

			// The response consists of a SignedData PKCS#7 [RFC2315], 
			// signed by the current CA (or RA) signing key.
			final List<X509Certificate> certs = new ArrayList<X509Certificate>();
			
			Collection<? extends Certificate> collection;
			try {
				CMSSignedData cmsMessageData = new CMSSignedData(getBytes(in));
				ContentInfo cmsContentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(cmsMessageData.getEncoded()));

				// TODO: This must be signed by the current CA.
				final SignedData sd = SignedData.getInstance(cmsContentInfo.getContent());
				if (SignedDataUtil.isSignedBy(sd, issuer) == false) {
					throw new IOException("Invalid Signer");
				}
				// The content of the SignedData PKCS#7 [RFC2315] is a degenerate
				// certificates-only Signed-data (Section 3.3) message containing the
				// new CA certificate and any new RA certificates, as defined in
				// Section 5.2.1.1.2, to be used when the current CA certificate
				// expires.
				CertStore store = SignedDataUtil.extractCertStore(sd);
				collection = store.getCertificates(new X509CertSelector());
			} catch (GeneralSecurityException e) {
				throw new IOException(e);
			} catch (CMSException e) {
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
	
	private byte[] getBytes(InputStream in) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		int i;
		while ((i = in.read()) != -1) {
			baos.write(i);
		}
		
		return baos.toByteArray();
	}
}
