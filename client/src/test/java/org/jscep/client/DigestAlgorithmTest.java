package org.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;

import org.jscep.response.Capability;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class DigestAlgorithmTest extends AbstractClientTest {
	@Test
	public void testDigestMD5() throws Exception {
		testDigest("MD5");
	}
	
	@Test
	public void testDigestSHA1() throws Exception {
		Assume.assumeTrue(client.getCaCapabilities().contains(Capability.SHA_1));
		
		testDigest("SHA-1");
	}
	
	@Ignore @Test(expected = IOException.class)
	public void testDigestSHA1Unsupported() throws Exception {
		Assume.assumeThat(client.getCaCapabilities().contains(Capability.SHA_1), is(false));
		
		testDigest("SHA-1");
	}
	
	@Test
	public void testDigestSHA256() throws Exception {
		Assume.assumeTrue(client.getCaCapabilities().contains(Capability.SHA_256));
		
		testDigest("SHA-256");
	}
	
	@Ignore @Test(expected = IOException.class)
	public void testDigestSHA256Unsupported() throws Exception {
		Assume.assumeThat(client.getCaCapabilities().contains(Capability.SHA_256), is(false));
		
		testDigest("SHA-256");
	}
	
	@Test
	public void testDigestSHA512() throws Exception {
		Assume.assumeTrue(client.getCaCapabilities().contains(Capability.SHA_512));
		
		testDigest("SHA-512");
	}
	
	@Ignore @Test(expected = IOException.class)
	public void testDigestSHA512Unsupported() throws Exception {
		Assume.assumeThat(client.getCaCapabilities().contains(Capability.SHA_512), is(false));
		
		testDigest("SHA-512");
	}
	
	private void testDigest(String digest) throws Exception {
		client.setPreferredDigestAlgorithm(digest);
		
		client.enrollCertificate(identity, keyPair, password);
	}
}
