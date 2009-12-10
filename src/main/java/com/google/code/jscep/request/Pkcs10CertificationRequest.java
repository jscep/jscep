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

package com.google.code.jscep.request;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * This class represents a PKCS#10 Certificate Request.
 *  */
public abstract class Pkcs10CertificationRequest {
	/**
	 * Returns the DER-encoded certification request.
	 *  
	 * @return the certification request.
	 * @throws GeneralSecurityException if any security error occurs.
	 * @throws IOException if any IO error occurs.
	 */
	public abstract byte[] getEncoded() throws GeneralSecurityException, IOException;
	
	/**
	 * Adds an attribute to the certification request.
	 * 
	 * @param oid the object identifier.
	 * @param attr the attribute.
	 */
	public abstract void addAttribute(String oid, Object attr);
	
	/**
	 * Creates a new instance of this class, using the preferred implementation.
	 *  
	 * @param keyPair the key pair used to sign the request.
	 * @param identity the certificate to sign.
	 * @return a new instance of this class.
	 */
	public static Pkcs10CertificationRequest getInstance(KeyPair keyPair, X509Certificate identity) {
		return new Pkcs10CertificationRequestImpl(keyPair, identity);
	}
}
