package org.jscep.client.verification;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class MessageDigestCertificateVerifierTest {
    @DataPoints
    public static MessageDigest[] getMessageDigests() throws Exception {
        List<MessageDigest> digests = new ArrayList<MessageDigest>();
        
        Set<String> algorithms = Security.getAlgorithms("MessageDigest");
        for (String algorithm : algorithms) {
            digests.add(MessageDigest.getInstance(algorithm));
        }
        
        return digests.toArray(new MessageDigest[0]);
    }
    
    @Theory
    public void testVerify(MessageDigest digest) throws Exception {
        X500Principal subject = new X500Principal("CN=example");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);
        
        byte[] expected = digest.digest(cert.getTBSCertificate());
        
        CertificateVerifier verifier = new MessageDigestCertificateVerifier(digest, expected);
        assertTrue(verifier.verify(cert));
    }

}
