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

package com.google.code.jscep.response;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This class represents the list of capabilities supported by a particular
 * SCEP server.
 */
public class Capabilities {
	private static Logger LOGGER = Logger.getLogger("com.google.code.jscep.response");
	/**
	 * This class represents a single SCEP server capability.
	 */
    public static enum Capability {
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
        
        private String capability;
        
        private Capability(String capability) {
        	this.capability = capability;
        }
        
        public String toString() {
        	return capability;
        }
    }
    
    private Set<Capability> set;
    
    /**
     * Creates a new Capabilities instance from the given list of
     * capabilities.
     * 
     * @param capabilities the list of capabilities.
     */
    public Capabilities(List<String> capabilities) {
    	set = EnumSet.noneOf(Capability.class);
    	
    	// http://tools.ietf.org/html/draft-nourse-scep-19#appendix-D.2
		// 
		// A client MUST be able to accept and ignore any unknown keywords 
		// that might be sent back by a CA.
    	for (Capability enumCap : Capability.values()) {
    		if (capabilities.contains(enumCap.toString())) {
    			set.add(enumCap);
    		}
    	}
    }

    private boolean supports(Capability capability) {
        return set.contains(capability);
    }

    /**
     * Returns <tt>true</tt> if the CA supports CA key rollover, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports CA key rollover, <tt>false</tt> otherwise.
     */
    public boolean supportsCaKeyRollover() {
        return supports(Capability.GET_NEXT_CA_CERT);
    }

    /**
     * Returns <tt>true</tt> if the CA supports HTTP POST requests, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports HTTP POST requests, <tt>false</tt> otherwise.
     */
    public boolean supportsPost() {
        return supports(Capability.POST_PKI_OPERATION);
    }

    /**
     * Returns <tt>true</tt> if the CA supports certificate renewal, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports certificate renewal, <tt>false</tt> otherwise.
     */
    public boolean supportsRenewal() {
        return supports(Capability.RENEWAL);
    }

    /**
     * Returns <tt>true</tt> if the CA supports SHA-1, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports SHA-1, <tt>false</tt> otherwise.
     */
    public boolean supportsSHA1() {
        return supports(Capability.SHA_1);
    }

    /**
     * Returns <tt>true</tt> if the CA supports SHA-256, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports SHA-256, <tt>false</tt> otherwise.
     */
    public boolean supportsSHA256() {
        return supports(Capability.SHA_256);
    }

    /**
     * Returns <tt>true</tt> if the CA supports SHA-512, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports SHA-512, <tt>false</tt> otherwise.
     */
    public boolean supportsSHA512() {
        return supports(Capability.SHA_512);
    }

    /**
     * Returns <tt>true</tt> if the CA supports TripleDES, <tt>false</tt> otherwise.
     * 
     * @return <tt>true</tt> if the CA supports TripleDES, <tt>false</tt> otherwise.
     */
    public boolean supportsTripleDES() {
        return supports(Capability.TRIPLE_DES);
    }
    
    /**
     * Returns the best cipher algorithm available.
     * <p>
     * In the case of this method, "best" is defined as most secure, so Triple DES
     * is preferred to DES.
     * 
     * @return the preferred cipher.
     * @link http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html#Cipher
     */
    public String getPreferredCipher() {
    	if (supportsTripleDES()) {
    		return "DESede";
    	} else {
    		return "DES";
    	}
    }
    
    /**
     * Returns the best message digest algorithm available.
     * <p>
     * In the case of this method, "best" is defined as most secure, so the order
     * of preference is as follows:
     * <ol>
     *     <li>SHA-512
     *     <li>SHA-256
     *     <li>SHA-1
     *     <li>MD5
     * </ol>
     * 
     * @return the preferred message digest algorithm.
     * @link http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html#MessageDigest
     */
    public String getPreferredMessageDigest() {
    	if (supportsSHA512()) {
    		return "SHA-512";
    	} else if (supportsSHA256()) {
    		return "SHA-256";
    	} else if (supportsSHA1()) {
    		return "SHA-1";
    	} else {
    		return "MD5";
    	}
    }

    @Override
    public String toString() {
    	final StringBuffer sb = new StringBuffer();
    	
    	sb.append(String.format("%-20s%s%n%n", "Capability", "Supported"));
    	for (Capability capability : Capability.values()) {
    		boolean supported;
    		if (set.contains(capability)) {
    			supported = true;
    		} else {
    			supported = false;
    		}
    		sb.append(String.format("%-20s%s%n", capability, supported));
    	}
    	
    	return sb.toString();
    }
}
