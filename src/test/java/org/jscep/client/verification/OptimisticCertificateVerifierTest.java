package org.jscep.client.verification;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class OptimisticCertificateVerifierTest {

    @Test
    public void testVerify() {
	CertificateVerifier verifier = new OptimisticCertificateVerifier();
	assertTrue(verifier.verify(mock(X509Certificate.class)));
    }

}
