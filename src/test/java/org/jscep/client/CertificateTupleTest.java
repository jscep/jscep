package org.jscep.client;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class CertificateTupleTest {
    private X509Certificate issuer;
    private X509Certificate signing;
    private X509Certificate encryption;
    private Authorities fixture;

    @Before
    public void setUp() {
        signing = null;
        encryption = null;
        issuer = null;
        fixture = new Authorities(signing, encryption, issuer);
    }

    @Test
    public void signingCertificateShouldBeSame() {
        Assert.assertEquals(signing, fixture.getVerifier());
    }

    @Test
    public void encryptionCertificateShouldBeSame() {
        Assert.assertEquals(encryption, fixture.getEncrypter());
    }

    @Test
    public void issuerCertificateShouldBeSame() {
        Assert.assertEquals(issuer, fixture.getIssuer());
    }
}
