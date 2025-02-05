package org.jscep.client.verification;

import static org.junit.Assert.assertFalse;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.jscep.util.X509Certificates;
import org.junit.Test;

public class PessimisticCertificateVerifierTest {
    @Test
    public void testVerify() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        X500Principal subject = new X500Principal("cn=example");
        X509Certificate cert = X509Certificates.createEphemeral(subject, keyPair);

        CertificateVerifier verifier = new PessimisticCertificateVerifier();
        assertFalse(verifier.verify(cert));
    }
}
