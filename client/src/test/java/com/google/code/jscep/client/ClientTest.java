package com.google.code.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.Transaction.State;
import com.google.code.jscep.x509.X509Util;

//@Ignore
public class ClientTest {
	private Client client;
	private KeyPair keyPair;
	private X509Certificate identity;
	private char[] password = "INBOUND_TLSuscl99".toCharArray();
	
	@Before
	public void setUp() throws Exception {
		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		identity = X509Util.createEphemeralCertificate(new X500Principal("CN=example.org"), keyPair);
		
		Client.Builder builder = new Client.Builder();
		builder.url(new URL("https://engtest66-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe"));
		builder.caFingerprint(new byte[] {-93, -44, 23, 25, -106, 116, 80, -113, 36, 23, 76, -89, -36, -18, 89, -59}, "MD5");
		builder.identity(identity, keyPair);
		builder.caIdentifier("foo");
		
		client = builder.build();
	}
	
	@BeforeClass
	public static void setUpTrustManager() throws Exception {
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, new TrustManager[] {new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		}}, null);
		HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
	}
	
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
	public void testRenewalEnrollDisallowed() throws Exception {
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
}
