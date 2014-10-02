package org.jscep.transport.response;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.EnumSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
        Provider[] providers = removeProviders();
        Capabilities caps = new Capabilities(Capability.TRIPLE_DES);
        assertThat(caps.getStrongestCipher(), is("DES"));

        restoreProviders(providers);
    }

    @Test
    public void testNoAlgorithmSupportYieldsDefaultDigest() {
        Provider[] providers = removeProviders();
        Capabilities caps = new Capabilities(Capability.SHA_512);
        assertThat(caps.getStrongestMessageDigest(), is(nullValue()));

        restoreProviders(providers);
    }
    
    @Test
    public void testStrongestSignature() throws NoSuchAlgorithmException {
    	Provider[] providers =removeProviders();
        BouncyCastleProvider bouncyCastle = new BouncyCastleProvider();
        Security.addProvider(bouncyCastle);
        assertThat(Security.getProviders().length, is(1));
        final EnumSet<Capability> capsConstructorArg = EnumSet.noneOf(Capability.class);
        for (Capability enumValue : Capability.values()) {
            capsConstructorArg.add(enumValue);
        }
        
        Capabilities caps = new Capabilities(capsConstructorArg.toArray(new Capability[capsConstructorArg.size()]));
        assertThat(caps.getStrongestMessageDigest().toString(), is(MessageDigest.getInstance("SHA-512").toString()));
        assertThat(caps.getStrongestSignatureAlgorithm(), is("SHA512withRSA"));
        
        removeProviders();
        restoreProviders(providers);
    }
    
	private void restoreProviders(Provider[] providers) {
		for (Provider provider : providers) {
            Security.addProvider(provider);
        }
	}

	private Provider[] removeProviders() {
		Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Security.removeProvider(provider.getName());
        }
		return providers;
	}
}
