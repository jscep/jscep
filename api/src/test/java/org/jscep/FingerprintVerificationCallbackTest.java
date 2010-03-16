package org.jscep;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FingerprintVerificationCallbackTest {
	private FingerprintVerificationCallback fixture;
	
	@Before
	public void setUp() throws Exception {
		final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		final X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
		
		fixture = new FingerprintVerificationCallback(identity);
	}
	
	/**
	 * MD2 is always available, but invalid in this case.
	 * 
	 * @throws Exception if any error occurs.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testInvalidAlgorithmMd2() throws Exception {
		fixture.getFingerprint("MD2");
	}
	
	/**
	 * SHA-384 is always available, but invalid in this case.
	 * 
	 * @throws Exception if any error occurs.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testInvalidAlgorithmSha384() throws Exception {
		fixture.getFingerprint("SHA-384");
	}
	
	@Test
	public void testGetFingerprintMd5() throws Exception {
		fixture.getFingerprint("MD5");
	}

	@Test
	public void testGetFingerprintSha() throws Exception {
		fixture.getFingerprint("SHA-1");
	}
	
	@Test
	public void testGetFingerprintSha256() throws Exception {
		fixture.getFingerprint("SHA-256");
	}
	
	@Test
	public void testGetFingerprintSha512() throws Exception {
		fixture.getFingerprint("SHA-512");
	}

	@Test
	public void testIsVerified() {
		Assert.assertFalse(fixture.isVerified());
	}

	@Test
	public void testSetVerified() {
		fixture.setVerified(true);
		Assert.assertTrue(fixture.isVerified());
	}
}
