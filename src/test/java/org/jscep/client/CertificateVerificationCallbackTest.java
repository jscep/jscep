package org.jscep.client;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.client.CertificateVerificationCallback;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;

public class CertificateVerificationCallbackTest {
    private CertificateVerificationCallback callback;
    private X509Certificate certificate;

    @Before
    public void setUp() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        X500Principal subject = new X500Principal("cn=example");

        certificate = X509Util.createEphemeralCertificate(subject, keyPair);
        callback = new CertificateVerificationCallback(certificate);
    }

    @Test
    public void testInitialVerifiedStateIsFalse() {
        assertThat(callback.isVerified(), is(false));
    }

    @Test
    public void testCertificateIsSame() {
        assertThat(callback.getCertificate(), is(certificate));
    }

    @Test
    public void testVerification() {
        callback.setVerified(true);
        assertThat(callback.isVerified(), is(true));
    }
}
