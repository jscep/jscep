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

package com.google.code.jscep.response;

/**
 * This class represents a single SCEP server capability.
 */
public enum Capability {
	/**
	 * CA Supports the GetNextCACert message.
	 */
    GET_NEXT_CA_CERT("GetNextCACert"),
    /**
     * PKIOPeration messages may be sent via HTTP POST.
     */
    POST_PKI_OPERATION("POSTPKIOperation"),
    /**
     * Clients may use current certificate and key to authenticate an enrollment request for a new certificate.
     */
    RENEWAL("Renewal"),
    /**
     * CA Supports the SHA-512 hashing algorithm in signatures and fingerprints.
     */
    SHA_512("SHA-512"),
    /**
     * CA Supports the SHA-256 hashing algorithm in signatures and fingerprints.
     */
    SHA_256("SHA-256"),
    /**
     * CA Supports the SHA-1 hashing algorithm in signatures and fingerprints.
     */
    SHA_1("SHA-1"),
    /**
     * CA Supports triple-DES for encryption.
     */
    TRIPLE_DES("DES3");
    
    /**
     * Member variable to hold the name of the capability as
     * defined in the SCEP Internet-Draft.
     */
    private String capability;
    
    /**
     * Constructs a new instance of this enum.
     * 
     * @param capability the name of the capability.
     */
    private Capability(String capability) {
    	this.capability = capability;
    }
    
    /**
     * Returns the name of the capability as defined in the
     * SCEP Internet-Draft.
     * 
     * @return the name of the capability.
     */
    @Override
    public String toString() {
    	return capability;
    }
}