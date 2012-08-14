package org.jscep.client;

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

import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.jscep.util.X509Certificates;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;

@Ignore
public abstract class AbstractClientTest extends ScepServerSupport {
    protected Client client;
    protected KeyPair keyPair;
    protected X509Certificate identity;
    protected char[] password = "password".toCharArray();

    @Before
    public void setUp() throws Exception {
	keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	identity = X509Certificates.createEphemeral(new X500Principal(
		"CN=jscep.org"), keyPair);

	final CallbackHandler cbh = new DefaultCallbackHandler(
		new OptimisticCertificateVerifier());

	client = new Client(getUrl(), cbh);
    }

    /**
     * Removes any trust checking for SSL connections.
     * 
     * @throws Exception
     *             if any error occurs.
     */
    @BeforeClass
    public static void setUpTrustManager() throws Exception {
	SSLContext ctx = SSLContext.getInstance("TLS");
	ctx.init(null, new TrustManager[] { new X509TrustManager() {
	    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
		    throws CertificateException {
	    }

	    public void checkServerTrusted(X509Certificate[] arg0, String arg1)
		    throws CertificateException {
	    }

	    public X509Certificate[] getAcceptedIssuers() {
		return null;
	    }
	} }, null);
	HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
	HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
	    public boolean verify(String hostname, SSLSession session) {
		return true;
	    }
	});
    }
}
