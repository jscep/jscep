package com.google.code.jscep.response;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import junit.framework.Assert;

import org.junit.Test;

public class CapabilitiesTest {
	private Capabilities createCapabilities() {
		return new Capabilities(new LinkedList<String>());
	}
	
	private Capabilities createCapabilities(String capability) {
		return new Capabilities(Collections.singletonList(capability));
	}
	
	private Capabilities createCapabilities(String... capabilities) {
		List<String> list = new LinkedList<String>();
		for (String capability : capabilities) {
			list.add(capability);
		}
		return new Capabilities(list);
	}
	
	@Test
	public void testSupportsCaKeyRollover() {
		Assert.assertTrue(createCapabilities("GetNextCACert").supportsCaKeyRollover());
	}
	
	@Test
	public void testSupportsCaKeyRolloverFalse() {
		Assert.assertFalse(createCapabilities().supportsCaKeyRollover());
	}

	@Test
	public void testSupportsPost() {
		Assert.assertTrue(createCapabilities("POSTPKIOperation").supportsPost());
	}
	
	@Test
	public void testSupportsPostFalse() {
		Assert.assertFalse(createCapabilities().supportsPost());
	}

	@Test
	public void testSupportsRenewal() {
		Assert.assertTrue(createCapabilities("Renewal").supportsRenewal());
	}
	
	@Test
	public void testSupportsRenewalFalse() {
		Assert.assertFalse(createCapabilities().supportsRenewal());
	}

	@Test
	public void testSupportsSHA1() {
		Assert.assertTrue(createCapabilities("SHA-1").supportsSHA1());
	}
	
	@Test
	public void testSupportsSHA1False() {
		Assert.assertFalse(createCapabilities().supportsSHA1());
	}

	@Test
	public void testSupportsSHA256() {
		Assert.assertTrue(createCapabilities("SHA-256").supportsSHA256());
	}
	
	@Test
	public void testSupportsSHA256False() {
		Assert.assertFalse(createCapabilities().supportsSHA256());
	}

	@Test
	public void testSupportsSHA512() {
		Assert.assertTrue(createCapabilities("SHA-512").supportsSHA512());
	}
	
	@Test
	public void testSupportsSHA512False() {
		Assert.assertFalse(createCapabilities().supportsSHA512());
	}

	@Test
	public void testSupportsTripleDES() {
		Assert.assertTrue(createCapabilities("DES3").supportsTripleDES());
	}
	
	@Test
	public void testSupportsTripleDESFalse() {
		Assert.assertFalse(createCapabilities().supportsTripleDES());
	}

	@Test
	public void testGetPreferredCipherTripleDES() {
		Assert.assertEquals("DESede", createCapabilities("DES3").getPreferredCipher());
	}
	
	@Test
	public void testGetPreferredCipherDES() {
		Assert.assertEquals("DES", createCapabilities().getPreferredCipher());
	}

	@Test
	public void testGetPreferredMessageDigestMD5() {
		Assert.assertEquals("MD5", createCapabilities().getPreferredMessageDigest());
	}
	
	@Test
	public void testGetPreferredMessageDigestSHA1() {
		Assert.assertEquals("SHA-1", createCapabilities("SHA-1").getPreferredMessageDigest());
	}
	
	@Test
	public void testGetPreferredMessageDigestSHA256() {
		Assert.assertEquals("SHA-256", createCapabilities("SHA-1", "SHA-256").getPreferredMessageDigest());
	}

	@Test
	public void testGetPreferredMessageDigestSHA512() {
		Assert.assertEquals("SHA-512", createCapabilities("SHA-1", "SHA-256", "SHA-512").getPreferredMessageDigest());
	}
}
