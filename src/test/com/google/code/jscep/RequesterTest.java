package com.google.code.jscep;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class RequesterTest {
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {

            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {

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

    @Test
    public void testAll() throws Exception {
        URL url = new URL("https://engtest81-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe");
        Requester client = new Requester(url);
        client.enroll(new X500Principal("CN=foo"), "foo".toCharArray());
//        client.getCert(BigInteger.ONE);
        client.getCrl();
    }

    class TestCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    pc.setPassword("foo".toCharArray());
                }
            }
        }
    }
}
