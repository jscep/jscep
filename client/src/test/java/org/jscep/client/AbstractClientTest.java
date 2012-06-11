package org.jscep.client;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.CallbackHandler;
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
	protected char[] password = "INBOUND_TLSuscl99".toCharArray();
	protected URL url;
	
	@Before
	public void setUp() throws Exception {
		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);

		url = new URL("https://192.168.11.73/ejbca/publicweb/apply/scep/noca/pkiclient.exe");
		final CallbackHandler cbh = new NoSecurityCallbackHandler();
		
		client = new Client(url, identity, keyPair.getPrivate(), cbh);
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
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});
	}
}
