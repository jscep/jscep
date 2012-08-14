package org.jscep.client.verification;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.Charsets;
import org.jscep.client.CertificateVerificationCallback;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.util.X509Certificates;
import org.junit.Before;
import org.junit.Test;

public class ConsoleCallbackVerifierTest {
    private X509Certificate cert;
    private CallbackHandler handler;

    @Before
    public void setUp() throws GeneralSecurityException {
	X500Principal subject = new X500Principal("CN=example");
	KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
	cert = X509Certificates.createEphemeral(subject, keyPair);
	handler = new DefaultCallbackHandler(new ConsoleCertificateVerifier());
    }

    @Test
    public void testYesResponse() throws Exception {
	CertificateVerificationCallback callback = getCallback();

	byte[] bytes = String.format("Y%n").getBytes(Charsets.US_ASCII.name());
	System.setIn(new ByteArrayInputStream(bytes));
	handler.handle(new Callback[] { callback });

	assertTrue(callback.isVerified());
    }

    private CertificateVerificationCallback getCallback() {
	return new CertificateVerificationCallback(cert);
    }

    @Test
    public void testEmptyResponse() throws Exception {
	CertificateVerificationCallback callback = getCallback();

	byte[] bytes = String.format("%n").getBytes(Charsets.US_ASCII.name());
	System.setIn(new ByteArrayInputStream(bytes));
	handler.handle(new Callback[] { callback });

	assertFalse(callback.isVerified());
    }

    @Test
    public void testNoResponse() throws Exception {
	CertificateVerificationCallback callback = getCallback();

	byte[] bytes = String.format("N%n").getBytes(Charsets.US_ASCII.name());
	System.setIn(new ByteArrayInputStream(bytes));
	handler.handle(new Callback[] { callback });

	assertFalse(callback.isVerified());
    }

    @Test
    public void testInvalidResponse() throws Exception {
	CertificateVerificationCallback callback = getCallback();

	byte[] bytes = String.format("X%nY%n").getBytes(
		Charsets.US_ASCII.name());
	System.setIn(new ByteArrayInputStream(bytes));
	handler.handle(new Callback[] { callback });

	assertTrue(callback.isVerified());
    }
}
