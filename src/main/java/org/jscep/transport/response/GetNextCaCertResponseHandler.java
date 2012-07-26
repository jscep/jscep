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
package org.jscep.transport.response;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.util.CertStoreUtils;
import org.jscep.util.SignedDataUtil;

/**
 * This class handles responses to <code>GetNextCACert</code> requests.
 * 
 * @author David Grant
 */
public class GetNextCaCertResponseHandler implements
        ScepResponseHandler<CertStore> {
    private static final String NEXT_CA_CERT = "application/x-x509-next-ca-cert";
    private final X509Certificate signer;

    public GetNextCaCertResponseHandler(X509Certificate signer) {
        this.signer = signer;
    }

    /**
     * {@inheritDoc}
     * 
     * @throws InvalidContentTypeException
     */
    public CertStore getResponse(byte[] content, String mimeType)
            throws ContentException {
        if (mimeType.startsWith(NEXT_CA_CERT)) {
            // http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

            // The response consists of a SignedData PKCS#7 [RFC2315],
            // signed by the current CA (or RA) signing key.
            try {
                CMSSignedData cmsMessageData = new CMSSignedData(content);
                ContentInfo cmsContentInfo = ContentInfo
                        .getInstance(cmsMessageData.getEncoded());

                final CMSSignedData sd = new CMSSignedData(cmsContentInfo);
                if (!SignedDataUtil.isSignedBy(sd, signer)) {
                    throw new InvalidContentException("Invalid Signer");
                }
                // The content of the SignedData PKCS#7 [RFC2315] is a
                // degenerate
                // certificates-only Signed-data (Section 3.3) message
                // containing the
                // new CA certificate and any new RA certificates, as defined in
                // Section 5.2.1.1.2, to be used when the current CA certificate
                // expires.
                return CertStoreUtils.fromSignedData(sd);
            } catch (IOException e) {
                throw new InvalidContentTypeException(e);
            } catch (CMSException e) {
                throw new InvalidContentTypeException(e);
            }
        } else {
            throw new InvalidContentTypeException(mimeType, NEXT_CA_CERT);
        }
    }
}
