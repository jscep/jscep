package org.jscep.client;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.util.X509Certificates;
import org.jscep.client.verification.CertificateVerifier;
import org.junit.Before;
import org.junit.Test;

public class DefaultCallbackHandlerTest {
    private CallbackHandler handler;
    private CertificateVerifier verifier;
    private X509Certificate cert;

    @Before
    public void setUp() throws Exception {
        verifier = mock(CertificateVerifier.class);
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        X500Principal subject = new X500Principal("cn=example");

        cert = X509Certificates.createEphemeral(subject, keyPair);
        handler = new DefaultCallbackHandler(verifier);
    }

    @Test(expected = UnsupportedCallbackException.class)
    public void testHandleForUnrecognisedCallback() throws IOException,
            UnsupportedCallbackException {
        handler.handle(new Callback[] { new LanguageCallback() });
    }

    @Test
    public void testHandleForCertificateVerificationCallbackTrue()
            throws IOException, UnsupportedCallbackException {
        CertificateVerificationCallback callback = getCallback();
        when(verifier.verify(cert)).thenReturn(true);
        handler.handle(new Callback[] { callback });

        assertTrue(callback.isVerified());
        verify(verifier).verify(cert);

    }

    @Test
    public void testHandleForCertificateVerificationCallbackFalse()
            throws IOException, UnsupportedCallbackException {
        CertificateVerificationCallback callback = getCallback();
        when(verifier.verify(cert)).thenReturn(false);
        handler.handle(new Callback[] { callback });

        assertFalse(callback.isVerified());
        verify(verifier).verify(cert);

    }

    private CertificateVerificationCallback getCallback() {
        return new CertificateVerificationCallback(cert);
    }

}
