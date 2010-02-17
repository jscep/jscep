package com.google.code.jscep.client;

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

import org.junit.Test;

import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.Transaction.State;
import com.google.code.jscep.x509.X509Util;

//@Ignore
public class ClientTest {

	@Test
	public void testEnroll() throws Exception {
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
		
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=example.org"), keyPair);

		final Client.Builder builder = new Client.Builder();
		builder.url(new URL("https://engtest66-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe"));
		builder.caFingerprint(new byte[] {-93, -44, 23, 25, -106, 116, 80, -113, 36, 23, 76, -89, -36, -18, 89, -59}, "MD5");
		builder.identity(identity, keyPair);
		builder.caIdentifier("foo");
		
		final Client client = builder.build();
		System.out.println(client.getCaCertificate());
		System.out.println(client.getCaCapabilities());
//		System.out.println(client.getNextCaCertificate());
		
		Transaction crlTrans = client.createTransaction();
		System.out.println(crlTrans.getCRL());
		
		Transaction enrollTrans = client.createTransaction();
		
		final char[] password = "INBOUND_TLSuscl99".toCharArray();
		State state = enrollTrans.enrollCertificate(identity, keyPair, password);
		if (state == State.CERT_ISSUED) {
			System.out.println(enrollTrans.getCertStore());
		}
	}
}
