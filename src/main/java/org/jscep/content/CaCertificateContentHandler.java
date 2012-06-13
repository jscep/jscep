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

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;


/**
 * This class handles responses to <code>GetCACert</code> requests.
 *
 * @author David Grant
 */
public class CaCertificateContentHandler implements ScepContentHandler<CertStore> {
    private static final String RA_CERT = "application/x-x509-ca-ra-cert";
	private static final String CA_CERT = "application/x-x509-ca-cert";
	private CertificateFactory factory;
	
	public CaCertificateContentHandler(CertificateFactory factory) {
		this.factory = factory;
	}

    /**
     * {@inheritDoc}
     * @throws InvalidContentTypeException 
     * @throws InvalidContentException 
     */
    public CertStore getContent(byte[] content, String mimeType) throws InvalidContentTypeException, InvalidContentException {
        if (mimeType.startsWith(CA_CERT)) {
            // http://tools.ietf.org/html/draft-nourse-scep-20#section-4.1.1.1
            try {
                X509Certificate ca = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(content));
                Collection<X509Certificate> caSet = Collections.singleton(ca);
                CertStoreParameters storeParams = new CollectionCertStoreParameters(caSet);

                return CertStore.getInstance("Collection", storeParams);
            } catch (GeneralSecurityException e) {
                throw new InvalidContentTypeException(e);
            }
        } else if (mimeType.startsWith(RA_CERT)) {
            // If an RA is in use, a certificates-only PKCS#7 SignedData
            // with a certificate chain consisting of both RA and CA certificates is
            // returned.
            // It should be in the order:
            // [0] RA
            // [1] CA
            try {
                if (content.length == 0) {
                    throw new InvalidContentException("Expected a SignedData object, but response was empty");
                }
                CMSSignedData sd = new CMSSignedData(content);

                return sd.getCertificatesAndCRLs("Collection", (String) null);
            } catch (GeneralSecurityException e) {
                throw new InvalidContentException(e);
            } catch (CMSException e) {
                throw new InvalidContentException(e);
            }
        } else {
        	throw new InvalidContentTypeException(mimeType, CA_CERT, RA_CERT);
        }
    }
}
