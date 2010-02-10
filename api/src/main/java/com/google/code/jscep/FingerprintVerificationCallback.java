package com.google.code.jscep;

import javax.security.auth.callback.Callback;

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
}
