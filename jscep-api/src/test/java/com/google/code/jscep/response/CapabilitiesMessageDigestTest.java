package com.google.code.jscep.response;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CapabilitiesMessageDigestTest {
	@Parameters
	public static Collection<Object[]> getParameters() {
		List<Object[]> params = new ArrayList<Object[]>();
		
		Capabilities capabilities;
		
		capabilities = new Capabilities();
		params.add(new Object[] {capabilities, "MD5"});
		capabilities = new Capabilities(Capability.SHA_1);
		params.add(new Object[] {capabilities, "SHA"});
		capabilities = new Capabilities(Capability.SHA_1, Capability.SHA_256);
		params.add(new Object[] {capabilities, "SHA-256"});
		capabilities = new Capabilities(Capability.SHA_1, Capability.SHA_256, Capability.SHA_512);
		params.add(new Object[] {capabilities, "SHA-512"});
		
		return params;
	}
	
	private final Capabilities capabilities;
	private final String algorithm;
	
	public CapabilitiesMessageDigestTest(Capabilities capabilities, String algorithm) {
		this.capabilities = capabilities;
		this.algorithm = algorithm;
	}
	
	@Test
	public void testStrongestMessageDigest() {
		Assert.assertEquals(algorithm, capabilities.getStrongestMessageDigest());
	}
}
