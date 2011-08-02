package org.jscep.client;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class CertificatePairTest {
    private X509Certificate signing;
    private X509Certificate encryption;
    private X509CertificatePair fixture;

    @Before
    public void setUp() {
        signing = null;
        encryption = null;
        fixture = new X509CertificatePair(signing, encryption);
    }

    @Test
    public void signingCertificateShouldBeSame() {
        Assert.assertEquals(signing, fixture.getSigning());
    }

    @Test
    public void encryptionCertificateShouldBeSame() {
        Assert.assertEquals(encryption, fixture.getEncryption());
    }
}
