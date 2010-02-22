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
package com.google.code.jscep;

import javax.security.auth.callback.Callback;

import com.google.code.jscep.util.HexUtil;

/**
 * This class is used to obtain verification of the fingerprint of a CA
 * certificate. 
 * 
 * @author David Grant
 */
public class FingerprintVerificationCallback implements Callback {
	private final byte[] fingerprint;
	private final String algorithm;
	private boolean verified;
	
	/**
	 * Construct a <code>FingerprintVerificationCallback</code> with the CA
	 * fingerprint and hash algorithm used to generate it.
	 * 
	 * @param fingerprint the CA fingerprint.
	 * @param algorithm the hash algorithm.
	 */
	public FingerprintVerificationCallback(byte[] fingerprint, String algorithm) {
		this.fingerprint = fingerprint;
		this.algorithm = algorithm;
	}
	
	/**
	 * Returns the hash algorithm used to construct the fingerprint.
	 * 
	 * @return the hash algorithm.
	 */
	public String getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * Returns the fingerprint of the CA certificate.
	 * 
	 * @return the fingerprint.
	 */
	public byte[] getFingerprint() {
		return fingerprint;
	}
	
	/**
	 * Returns the outcome of the callback.
	 * <p>
	 * If the CA certificate fingerprint was confirmed, this method 
	 * returns <code>true</code>; and <code>false</code> if the fingerprint 
	 * could not be confirmed, or did not match.
	 * 
	 * @return the outcome.
	 */
	public boolean isVerified() {
		return verified;
	}
	
	/**
	 * Sets the outcome of the callback.
	 * <p>
	 * If the CA certificate fingerprint was confirmed, this method should
	 * be called with an argument of <code>true</code>.  If the fingerprint
	 * can not be confirmed, the argument should be <code>false</code>.
	 * 
	 * @param verified the outcome.
	 */
	public void setVerified(boolean verified) {
		this.verified = verified;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		final StringBuilder builder = new StringBuilder(algorithm);
		builder.append(' ');
		builder.append(HexUtil.toHexString(fingerprint));
		builder.append(' ');
		if (verified) {
			builder.append("(Verified)");
		} else {
			builder.append("(Unverified)");
		}
		
		return builder.toString();
	}
}
