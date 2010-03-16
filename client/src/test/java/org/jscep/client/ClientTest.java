package org.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.x509.X509Util;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

public class ClientTest extends AbstractClientTest {
	/**
	 * The requester MUST use RSA keys for all symmetric key operations.
	 * 
	 * @throws Exception if any error occurs.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testRsa() throws Exception {
		final KeyPair keyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
		final X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
		final URL url = new URL("http://jscep.org/pkiclient.exe");
		
		new Client(url, identity, keyPair.getPrivate(), new NoSecurityCallbackHandler());
	}
	
	@Ignore @Test
	public void testRenewalEnrollAllowed() throws Exception {
		// Ignore this test if the CA doesn't support renewal.
		Assume.assumeTrue(client.getCaCapabilities().isRenewalSupported());
		
		Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
	}

	/**
	 * CAs that do advertise support for renewal should not perform it!
	 * 
	 * @throws Exception
	 */
	@Ignore @Test(expected = IOException.class)
	public void testRenewalSameCAEnrollDisallowed() throws Exception {
		// Ignore if renewal is supported.
		Assume.assumeThat(client.getCaCapabilities().isRenewalSupported(), is(false));

		Transaction trans;
		State state;
		
		trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		state = trans.getState();
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
		
		trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		state = trans.getState();
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
	}

	@Ignore @Test
	public void testEnroll() throws Exception {		
		Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
	}
	
	@Ignore @Test
	public void testEnrollThenGet() throws Exception {		
		final Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		State state = trans.getState();
		Assume.assumeTrue(state == State.CERT_ISSUED);
		identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		Certificate retrieved = client.getCertificate(identity.getSerialNumber()).iterator().next();
		
		Assert.assertEquals(identity, retrieved);
	}
	
	@Ignore @Test(expected = IOException.class)
	public void testEnrollInvalidPassword() throws Exception {
		Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), new char[0]);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
	}
}
