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

import java.security.Security;
import java.util.EnumSet;
import java.util.Set;
import java.util.logging.Logger;

import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents a set of capabilities for a particular
 * SCEP server.
 * 
 * @author davidjgrant1978
 */
public class Capabilities {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.response");
	private EnumSet<Capability> capabilities;

	/**
	 * Constructs a new instance of this class with the specified
	 * capabilities.
	 * 
	 * @param capabilities the capabilities.
	 */
	public Capabilities(Capability... capabilities) {
		this.capabilities = EnumSet.noneOf(Capability.class);

		for (Capability capability : capabilities) {
			this.capabilities.add(capability);
		}
	}
	
	/**
	 * Add the specified capability to this capabilities set.
	 * 
	 * @param capability the capability to add.
	 */
	public void add(Capability capability) {
		capabilities.add(capability);
	}
	
	/**
	 * Returns <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
	 *  
	 * @return <tt>true</tt> if POST is supported, <tt>false</tt> otherwise.
	 */
	public boolean isPostSupported() {
		return capabilities.contains(Capability.POST_PKI_OPERATION);
	}
	
	/**
	 * Returns <tt>true</tt> if retrieval of the next CA is supported, <tt>false</tt> otherwise.
	 *  
	 * @return <tt>true</tt> if retrieval of the next CA is supported, <tt>false</tt> otherwise.
	 */
	public boolean isNextCASupported() {
		return capabilities.contains(Capability.GET_NEXT_CA_CERT);
	}
	
	/**
	 * Returns <tt>true</tt> if certificate renewal is supported, <tt>false</tt> otherwise.
	 *  
	 * @return <tt>true</tt> if certificate renewal is supported, <tt>false</tt> otherwise.
	 */
	public boolean isRenewalSupported() {
		return capabilities.contains(Capability.RENEWAL);
	}
	
	/**
	 * Returns the strongest cipher algorithm supported by the server and client.
	 * <p>
	 * The algorithms are ordered thus:
	 * <ol>
	 *     <li>Triple DES</li>
	 *     <li>DES</li>
	 * </ol>
	 * 
	 * @return the strongest cipher algorithm supported by the server and client.
	 */
	public String getStrongestCipher() {
		LOGGER.entering(getClass().getName(), "getStrongestCipher");
		final Set<String> ciphers = Security.getAlgorithms("Cipher");
		
		final String cipher;
		if (ciphers.contains("DESEDE") && capabilities.contains(Capability.TRIPLE_DES)) {
			cipher = "DESEDE";
		} else {
			cipher = "DES";
		}
		
		LOGGER.exiting(getClass().getName(), "getStrongestCipher", cipher);
		return cipher;
	}
	
	/**
	 * Returns the strongest message digest algorithm supported by the server and client.
	 * <p>
	 * The algorithms are ordered thus:
	 * <ol>
	 *     <li>SHA-512</li>
	 *     <li>SHA-256</li>
	 *     <li>SHA-1</li>
	 *     <li>MD5</li>
	 * </ol>
	 * 
	 * @return the strongest message digest algorithm supported by the server and client.
	 */
	public String getStrongestMessageDigest() {
		
		final Set<String> digests = Security.getAlgorithms("MessageDigest");
		
		final String digest;
		if (digests.contains("SHA-512") && capabilities.contains(Capability.SHA_512)) {
			digest = "SHA-512";
		} else if (digests.contains("SHA-256") && capabilities.contains(Capability.SHA_256)) {
			digest = "SHA-256";
		} else if (digests.contains("SHA") && capabilities.contains(Capability.SHA_1)) {
			digest = "SHA";
		} else {
			digest = "MD5";
		}
		
		LOGGER.exiting(getClass().getName(), "getStrongestMessageDigest()", digest);
		return digest;
	}
	
	@Override
	public String toString() {
		return capabilities.toString();
	}
}
