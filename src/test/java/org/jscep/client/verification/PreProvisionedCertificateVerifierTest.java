package org.jscep.client.verification;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.Test;

public class PreProvisionedCertificateVerifierTest {

    @Test
    public void testVerify() throws Exception {
        X500Principal subject = new X500Principal("CN=example");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);
        
        CertificateVerifier verifier = new PreProvisionedCertificateVerifier(cert);
        assertTrue(verifier.verify(cert));
    }

}
