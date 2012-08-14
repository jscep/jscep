package org.jscep.client.verification;

import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class PessimisticCertificateVerifierTest {
    @Test
    public void testVerify() {
	CertificateVerifier verifier = new PessimisticCertificateVerifier();
	assertFalse(verifier.verify(mock(X509Certificate.class)));
    }
}
