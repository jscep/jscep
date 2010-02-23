package com.google.code.jscep;

import org.jscep.FingerprintVerificationCallback;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FingerprintVerificationCallbackTest {
	private FingerprintVerificationCallback fixture;
	private byte[] fingerprint = new byte[0];
	private String algorithm = "MD5";
	
	@Before
	public void setUp() {
		fixture = new FingerprintVerificationCallback(fingerprint, algorithm);
	}
	
	@Test
	public void testGetAlgorithm() {
		Assert.assertEquals(algorithm, fixture.getAlgorithm());
	}

	@Test
	public void testGetFingerprint() {
		Assert.assertArrayEquals(fingerprint, fixture.getFingerprint());
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
