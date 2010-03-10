package org.jscep.client;

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

import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;

@Ignore
public abstract class AbstractClientTest {
	protected Client client;
	protected KeyPair keyPair;
	protected X509Certificate identity;
	protected char[] password = "secret".toCharArray();
	
	@Before
	public void setUp() throws Exception {
		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
		
		Client.Builder builder = new Client.Builder();
		builder.url(new URL("http://jscep.org/scep/pkiclient.exe"));
		builder.caFingerprint(new byte[] {-93, -44, 23, 25, -106, 116, 80, -113, 36, 23, 76, -89, -36, -18, 89, -59});
		builder.identity(identity, keyPair);
		builder.caIdentifier("foo");
		
		client = builder.build();
	}
	
	/**
	 * Removes any trust checking for SSL connections.
	 * 
	 * @throws Exception if any error occurs.
	 */
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
}
