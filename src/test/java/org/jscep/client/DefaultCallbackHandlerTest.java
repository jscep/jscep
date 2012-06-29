package org.jscep.client;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.CertificateVerificationCallback;
import org.jscep.client.verification.CertificateVerifier;
import org.junit.Before;
import org.junit.Test;

public class DefaultCallbackHandlerTest {
    private CallbackHandler handler;
    private CertificateVerifier verifier;
    private X509Certificate cert;

    @Before
    public void setUp() {
        verifier = mock(CertificateVerifier.class);
        cert = mock(X509Certificate.class);
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
