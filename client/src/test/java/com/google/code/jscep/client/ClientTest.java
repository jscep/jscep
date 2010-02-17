package com.google.code.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.Transaction.State;

//@Ignore
public class ClientTest extends AbstractClientTest {
	@Test
	public void testRenewalEnrollAllowed() throws Exception {
		// Ignore this test if the CA doesn't support renewal.
		Assume.assumeTrue(client.getCaCapabilities().isRenewalSupported());
		
		Transaction trans = client.createTransaction();		
		State state = trans.enrollCertificate(identity, keyPair, password);
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
		
		Transaction trans = client.createTransaction();		
		State state;
		state = trans.enrollCertificate(identity, keyPair, password);
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
		state = trans.enrollCertificate(identity, keyPair, password);
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
	}

	@Test
	public void testEnroll() throws Exception {		
		Transaction trans = client.createTransaction();		
		State state = trans.enrollCertificate(identity, keyPair, password);
		if (state == State.CERT_ISSUED) {
			trans.getCertStore().getCertificates(null);
		}
	}
	
	@Test(expected = IOException.class)
	public void testEnrollInvalidPassword() throws Exception {
		Transaction trans = client.createTransaction();		
		State state = trans.enrollCertificate(identity, keyPair, new char[0]);
		if (state == State.CERT_ISSUED) {
			trans.getCertStore().getCertificates(null);
		}
	}
}
