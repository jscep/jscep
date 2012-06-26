package org.jscep.client;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.jscep.server.ScepServletImpl;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;

import javax.net.ssl.*;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Ignore
public abstract class AbstractClientTest {
    private static String PATH = "/scep/pkiclient.exe";
    protected Client client;
    protected KeyPair keyPair;
    protected X509Certificate identity;
    protected char[] password = "password".toCharArray();
    protected URL url;
    private Server server;
    private int port;

    @Before
    public void setUp() throws Exception {
        final ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(ScepServletImpl.class, PATH);

        server = new Server(0);
        server.setHandler(handler);
        server.start();

        port = server.getConnectors()[0].getLocalPort();
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        identity = X509Util.createEphemeralCertificate(new X500Principal(
                "CN=jscep.org"), keyPair);

        url = new URL("http", "localhost", port, PATH);
        final CallbackHandler cbh = new NoSecurityCallbackHandler();

        client = new Client(url, identity, keyPair.getPrivate(), cbh);
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
