package org.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import junit.framework.Assert;

import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;


@Ignore
public class ClientTest extends AbstractClientTest {
	@Test
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

	@Test
	public void testEnroll() throws Exception {		
		Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
	}
	
	@Test
	public void testEnrollThenGet() throws Exception {		
		final Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), password);
		State state = trans.getState();
		Assume.assumeTrue(state == State.CERT_ISSUED);
		identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		Certificate retrieved = client.getCertificate(identity.getSerialNumber()).iterator().next();
		
		Assert.assertEquals(identity, retrieved);
	}
	
	@Test(expected = IOException.class)
	public void testEnrollInvalidPassword() throws Exception {
		Transaction trans = client.enrollCertificate(identity, keyPair.getPrivate(), new char[0]);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
	}
}
