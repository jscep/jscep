package org.jscep.transport.response;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RunWith(Parameterized.class)
public class CapabilitiesCipherTest {
    @Parameters
    public static Collection<Object[]> getParameters() {
        List<Object[]> params = new ArrayList<Object[]>();

        Capabilities capabilities;

        capabilities = new Capabilities();
        params.add(new Object[] { capabilities, "DES" });
        capabilities = new Capabilities(Capability.TRIPLE_DES);
        params.add(new Object[] { capabilities, "DESede" });
        capabilities = new Capabilities(Capability.TRIPLE_DES, Capability.AES);
        params.add(new Object[] { capabilities, "AES" });
        capabilities = new Capabilities(Capability.SCEP_STANDARD);
        params.add(new Object[] { capabilities, "AES" });

        return params;
    }

    private final Capabilities capabilities;
    private final String algorithm;

    public CapabilitiesCipherTest(Capabilities capabilities, String algorithm) {
        this.capabilities = capabilities;
        this.algorithm = algorithm;
    }

    @Test
    public void testStrongestCipher() {
        Assert.assertEquals(algorithm, capabilities.getStrongestCipher());
    }
}
