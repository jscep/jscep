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
package org.jscep;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.callback.Callback;


/**
 * This class is used to obtain verification of the fingerprint of a CA
 * certificate.
 * <p>
 * The SCEP specification states that the CA certificate must be provided
 * out-of-band, and that the CA certificate fingerprint MAY be used to authenticate
 * that certificate.  The specification also states that only particular algorithms
 * may be used to create the fingerprint, so we allow the client to choose the
 * algorithm fingerprint, whilst keeping the CA certificate secret.
 * <p>
 * Use of the term MAY in the above statement means that other forms of authentication
 * should be acceptable, but it should be fairly trivial for clients to figure out the
 * hash.
 * 
 * @author David Grant
 */
public class FingerprintVerificationCallback implements Callback {
	private static final Set<String> VALID_ALGORITHMS = new HashSet<String>();
	static {
		VALID_ALGORITHMS.add("SHA-1");
		VALID_ALGORITHMS.add("SHA-256");
		VALID_ALGORITHMS.add("SHA-512");
		VALID_ALGORITHMS.add("MD5");
	}
	private final X509Certificate caCertificate;
	private boolean verified;
	
	/**
	 * Construct a <code>FingerprintVerificationCallback</code> with the CA
	 * fingerprint and hash algorithm used to generate it.
	 * 
	 * @param fingerprint the CA fingerprint.
	 * @param algorithm the hash algorithm.
	 * @throws IllegalArgumentException if the algorithm is invalid.
	 */
	public FingerprintVerificationCallback(X509Certificate caCertificate) throws IllegalArgumentException {
		this.caCertificate = caCertificate;
	}

	/**
	 * Returns the fingerprint of the CA certificate.
	 * <p>
	 * The only valid algorithms here are:
	 * <ul>
	 *     <li>SHA-1</li>
	 *     <li>SHA-256</li>
	 *     <li>SHA-512</li>
	 *     <li>MD5</li>
	 * </ul>
	 * 
	 * @param hashAlgorithm the hash algorithm name.
	 * @return the fingerprint.
	 * @throws NoSuchAlgorithmException if the algorithm is not supported by the JCA.
	 * @throws CertificateEncodingException if the CA certificate cannot be decoded.
	 */
	public byte[] getFingerprint(String hashAlgorithm) throws IllegalArgumentException, NoSuchAlgorithmException, CertificateEncodingException {
		if (VALID_ALGORITHMS.contains(hashAlgorithm) == false) {
			throw new IllegalArgumentException("Algorithm must be one of SHA-1, SHA-256, SHA-512 or MD5.  Was " + hashAlgorithm);
		}
		final MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		digest.update(caCertificate.getTBSCertificate());
		
		return digest.digest();
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
}
