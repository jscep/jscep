package org.jscep.client.verification;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.jscep.util.X509Certificates;
import org.junit.Before;
import org.junit.Test;

public class CachingCertificateVerifierTest {
    private X509Certificate cert;

    @Before
    public void setUp() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        X500Principal subject = new X500Principal("cn=example");

        cert = X509Certificates.createEphemeral(subject, keyPair);
    }

    @Test
    public void testVerifyDelegates() {
        CertificateVerifier delegate = mock(CertificateVerifier.class);
        when(delegate.verify(cert)).thenReturn(true);

        CertificateVerifier verifier = new CachingCertificateVerifier(delegate);
        assertTrue(verifier.verify(cert));

        verify(delegate).verify(cert);
    }

    @Test
    public void testVerifyCachesDelegateAnswer() {
        CertificateVerifier delegate = mock(CertificateVerifier.class);
        when(delegate.verify(cert)).thenReturn(true).thenReturn(false);

        CertificateVerifier verifier = new CachingCertificateVerifier(delegate);
        assertTrue(verifier.verify(cert));
        assertTrue(verifier.verify(cert));

        verify(delegate, times(1)).verify(cert);
    }
}
