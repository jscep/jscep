package com.google.code.jscep.client;

import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;

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

		final Client.Builder builder = new Client.Builder();
		builder.url(new URL("https://engtest66-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe"));
		builder.caDigest(new byte[] {-93, -44, 23, 25, -106, 116, 80, -113, 36, 23, 76, -89, -36, -18, 89, -59}, "MD5");
		builder.subject(new X500Principal("CN=example.org"));
		builder.caIdentifier("foo");
		
		final Client client = builder.build();
		System.out.println(client.enroll("INBOUND_TLSuscl99".toCharArray(), 60L));
	}
}
