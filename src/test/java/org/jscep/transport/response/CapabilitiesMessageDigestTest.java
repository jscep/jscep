package org.jscep.transport.response;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.Capability;
import org.junit.Assert;
import org.junit.Assume;
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
	params.add(new Object[] { capabilities, "MD5" });
	capabilities = new Capabilities(Capability.SHA_1);
	params.add(new Object[] { capabilities, "SHA-1" });
	capabilities = new Capabilities(Capability.SHA_1, Capability.SHA_256);
	params.add(new Object[] { capabilities, "SHA-256" });
	capabilities = new Capabilities(Capability.SHA_1, Capability.SHA_256,
		Capability.SHA_512);
	params.add(new Object[] { capabilities, "SHA-512" });

	return params;
    }

    private final Capabilities capabilities;
    private final String algorithm;

    public CapabilitiesMessageDigestTest(Capabilities capabilities,
	    String algorithm) {
	this.capabilities = capabilities;
	this.algorithm = algorithm;
    }

    @Test
    public void testStrongestMessageDigest() {
	Assume.assumeTrue(algorithmExists(algorithm));
	Assert.assertEquals(algorithm, capabilities.getStrongestMessageDigest());
    }

    private boolean algorithmExists(String algorithm) {
	for (Provider provider : Security.getProviders()) {
	    for (Service service : provider.getServices()) {
		if (service.getType().equals("MessageDigest")
			&& service.getAlgorithm().equals(algorithm)) {
		    return true;
		}
	    }
	}

	return false;
    }
}
