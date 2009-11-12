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

import java.net.ContentHandler;
import java.net.ContentHandlerFactory;

public class ScepContentHandlerFactory implements ContentHandlerFactory {
	/**
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.2.1
	 */
    private static final String PKI_MESSAGE = "application/x-pki-message";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#appendix-D.2
     */
    private static final String TEXT_PLAIN = "text/plain";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.1
     */
    private static final String X509_CA_CERT = "application/x-x509-ca-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.2
     */
    private static final String X509_CA_RA_CERT = "application/x-x509-ca-ra-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.6.1
     */
    private static final String X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";

    public ContentHandler createContentHandler(String mimeType) {
        if (mimeType.equals(TEXT_PLAIN)) {
            return new CaCapabilitiesResponseHandler();
        } else if (mimeType.equals(PKI_MESSAGE)) {
            return new CertRepResponseHandler();
        } else if (mimeType.equals(X509_CA_CERT)) {
            return new CaCertificateResponseHandler();
        } else if (mimeType.equals(X509_CA_RA_CERT)) {
            return new CaRaCertificateResponseHandler();
        } else if (mimeType.equals(X509_NEXT_CA_CERT)) {
            return null;
        } else {
            return null;
        }
    }
}
