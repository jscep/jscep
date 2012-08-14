package org.jscep.client.verification;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class CachingCertificateVerifierTest {
    @Test
    public void testVerifyDelegates() {
	X509Certificate cert = mock(X509Certificate.class);

	CertificateVerifier delegate = mock(CertificateVerifier.class);
	when(delegate.verify(cert)).thenReturn(true);

	CertificateVerifier verifier = new CachingCertificateVerifier(delegate);
	assertTrue(verifier.verify(cert));

	verify(delegate).verify(cert);
    }

    @Test
    public void testVerifyCachesDelegateAnswer() {
	X509Certificate cert = mock(X509Certificate.class);

	CertificateVerifier delegate = mock(CertificateVerifier.class);
	when(delegate.verify(cert)).thenReturn(true).thenReturn(false);

	CertificateVerifier verifier = new CachingCertificateVerifier(delegate);
	assertTrue(verifier.verify(cert));
	assertTrue(verifier.verify(cert));

	verify(delegate, times(1)).verify(cert);
    }
}
