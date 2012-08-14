package org.jscep.transport.response;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.Capability;
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

    @Test
    public void testContains() {
	Capabilities caps = new Capabilities(Capability.GET_NEXT_CA_CERT);
	assertTrue(caps.contains(Capability.GET_NEXT_CA_CERT));
    }

    @Test
    public void testNoAlgorithmSupportYieldsDefaultCipher() {
	Provider[] providers = Security.getProviders();
	for (Provider provider : providers) {
	    Security.removeProvider(provider.getName());
	}
	Capabilities caps = new Capabilities(Capability.TRIPLE_DES);
	assertThat(caps.getStrongestCipher(), is("DES"));

	for (Provider provider : providers) {
	    Security.addProvider(provider);
	}
    }

    @Test
    public void testNoAlgorithmSupportYieldsDefaultDigest() {
	Provider[] providers = Security.getProviders();
	for (Provider provider : providers) {
	    Security.removeProvider(provider.getName());
	}
	Capabilities caps = new Capabilities(Capability.SHA_512);
	assertThat(caps.getStrongestMessageDigest(), is("MD5"));

	for (Provider provider : providers) {
	    Security.addProvider(provider);
	}
    }
}
