package org.jscep.response;

import org.junit.Assert;
import org.junit.Test;

public class CapabilitiesTest {
	@Test
	public void testPostNotSupported() {
		Capabilities caps = new Capabilities();
		Assert.assertFalse(caps.isPostSupported());
	}
	
	@Test
	public void testPostSupported() {
		Capabilities caps = new Capabilities(Capability.POST_PKI_OPERATION);
		Assert.assertTrue(caps.isPostSupported());
	}
	
	@Test
	public void testRenewalNotSupported() {
		Capabilities caps = new Capabilities();
		Assert.assertFalse(caps.isRenewalSupported());
	}
	
	@Test
	public void testRenewalSupported() {
		Capabilities caps = new Capabilities(Capability.RENEWAL);
		Assert.assertTrue(caps.isRenewalSupported());
	}
	
	@Test
	public void testNextCANotSupported() {
		Capabilities caps = new Capabilities();
		Assert.assertFalse(caps.isRolloverSupported());
	}
	
	@Test
	public void testNextCASupported() {
		Capabilities caps = new Capabilities(Capability.GET_NEXT_CA_CERT);
		Assert.assertTrue(caps.isRolloverSupported());
	}
}
