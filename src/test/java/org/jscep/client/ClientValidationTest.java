package org.jscep.client;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;

public class ClientValidationTest {
    private X500Principal subject;

    private KeyPair dsaKeyPair;
    private PrivateKey dsaPrivateKey;
    private X509Certificate dsaCertificate;

    private KeyPair rsaKeyPair;
    private PrivateKey rsaPrivateKey;
    private X509Certificate rsaCertificate;

    @Before
    public void setUp() {
        subject = new X500Principal("CN=jscep");

        dsaKeyPair = getKeyPair("DSA");
        dsaPrivateKey = dsaKeyPair.getPrivate();
        dsaCertificate = getCertificate(dsaKeyPair);

        rsaKeyPair = getKeyPair("RSA");
        rsaPrivateKey = rsaKeyPair.getPrivate();
        rsaCertificate = getCertificate(rsaKeyPair);
    }

    @Test(expected = NullPointerException.class)
    public void testNullUrl() {
        new Client(null, null, null, null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullIdentity() {
        new Client(getUrl(), null, null, null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPrivateKey() {
        new Client(getUrl(), rsaCertificate, null, null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullCallbackHandler() {
        new Client(getUrl(), rsaCertificate, rsaPrivateKey, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKeyAlgorithmPublic() {
        new Client(getUrl(), dsaCertificate, rsaPrivateKey,
                getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKeyAlgorithmPrivate() {
        new Client(getUrl(), rsaCertificate, dsaPrivateKey,
                getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidUrlProtocol() {
        new Client(getUrl("ftp"), rsaCertificate, rsaPrivateKey,
                getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithReference() {
        new Client(getUrlWithReference(), rsaCertificate, rsaPrivateKey,
                getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithQueryString() {
        new Client(getUrlWithQueryString(), rsaCertificate, rsaPrivateKey,
                getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeyMismatch() {
        new Client(getUrl(), rsaCertificate, getPrivateKey("RSA"),
                getCallbackHandler());
    }

    private URL getUrlWithQueryString() {
        try {
            return new URL("http://jscep.org/pkiclient.exe?key=value");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private URL getUrlWithReference() {
        try {
            return new URL("http://jscep.org/pkiclient.exe#reference");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private URL getUrl(String protocol) {
        try {
            return new URL(protocol, "jscep.org", "pkiclient.exe");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey getPrivateKey(String algorithm) {
        return getKeyPair(algorithm).getPrivate();
    }

    private X509Certificate getCertificate(KeyPair keyPair) {
        try {
            return X509Util.createEphemeralCertificate(subject, keyPair);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private KeyPair getKeyPair(String algorithm) {
        try {
            return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private CallbackHandler getCallbackHandler() {
        return new DefaultCallbackHandler(new OptimisticCertificateVerifier());
    }

    private PrivateKey getPrivateKey() {
        return getPrivateKey("RSA");
    }

    private X509Certificate getCertificate() {
        return getCertificate(rsaKeyPair);
    }

    private URL getUrl() {
        return getUrl("http");
    }
}
