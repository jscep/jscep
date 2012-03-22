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
package org.jscep.response;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.EnumSet;


/**
 * This class represents a set of capabilities for a particular
 * SCEP server.
 * 
 * @author David Grant
 */
public class Capabilities {
	private EnumSet<Capability> capabilities;

	/**
	 * Constructs a new instance of this class with the specified
	 * capabilities.
	 * 
	 * @param capabilities the capabilities.
	 */
	public Capabilities(Capability... capabilities) {
		this.capabilities = EnumSet.noneOf(Capability.class);
        Collections.addAll(this.capabilities, capabilities);
	}
	
	/**
	 * Add the provided capability to this capabilities set.
	 * 
	 * @param capability the capability to add.
	 */
	public void add(Capability capability) {
		capabilities.add(capability);
	}
	
	/**
	 * Returns <code>true</code> if the server supports the provided
	 * Capability, <code>false</code> otherwise.
	 * 
	 * @param capability the capability to test for.
	 * @return <code>true</code> if the server supports the provided
	 * 	Capability, <code>false</code> otherwise.
	 */
	public boolean contains(Capability capability) {
		return capabilities.contains(capability);
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
	public boolean isRolloverSupported() {
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
	 *     <li>DESede ("Triple DES")</li>
	 *     <li>DES</li>
	 * </ol>
	 * 
	 * @return the strongest cipher algorithm supported by the server and client.
	 */
	public String getStrongestCipher() {
		final String cipher;
		if (cipherExists("DESede") && capabilities.contains(Capability.TRIPLE_DES)) {
			cipher = "DESede";
		} else {
			cipher = "DES";
		}
		
		return cipher;
	}
	
	private boolean cipherExists(String cipher) {
		try {
			Cipher.getInstance(cipher);
			return true;
		} catch (GeneralSecurityException e) {
			return false;
		}
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
		final String digest;
		if (digestExists("SHA-512") && capabilities.contains(Capability.SHA_512)) {
			digest = "SHA-512";
		} else if (digestExists("SHA-256") && capabilities.contains(Capability.SHA_256)) {
			digest = "SHA-256";
		} else if (digestExists("SHA-1") && capabilities.contains(Capability.SHA_1)) {
			digest = "SHA-1";
		} else {
			digest = "MD5";
		}
		
		return digest;
	}
	
	private boolean digestExists(String digest) {
		try {
			MessageDigest.getInstance(digest);
			return true;
		} catch (GeneralSecurityException e) {
			return false;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return capabilities.toString();
	}
}
