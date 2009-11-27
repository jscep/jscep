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

/**
 * This interface represents a mechanism for handling specific SCEP content.
 * 
 * @param <T> the content that is handled by the implementation of this interface.
 */
public interface ScepContentHandler<T> {
	/**
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.2.1
	 */
	String PKI_MESSAGE = "application/x-pki-message";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#appendix-D.2
     */
	String TEXT_PLAIN = "text/plain";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.1
     */
    String X509_CA_CERT = "application/x-x509-ca-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.2
     */
    String X509_CA_RA_CERT = "application/x-x509-ca-ra-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.6.1
     */
    String X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
	
    /**
     * Read and interpret the content from the input stream.
     * 
     * @param in the input stream containing the content.
     * @param mimeType the type of the input stream.
     * @return the content in a usage form.
     * @throws IOException if any I/O error occurs.
     */
	T getContent(InputStream in, String mimeType) throws IOException;
}
