/*
 * Copyright (c) 2009 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.google.code.jscep;

import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class RequesterTest {
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new DefaultTrustManager()}, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(new DefaultHostnameVerifier());
    }

    @Test
    public void testAll() throws Exception {
    	X500Principal subject = new X500Principal("CN=jscep.googlecode.com");
    	byte[] digest = Hex.decode("3D7CE8C2D362200B2593FD2E935BDFB2".getBytes());
    	
        URL url = new URL("https://engtest81-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe");
        Requester client = new Requester.Builder(url)
        								.subject(subject)
        								.fingerprint(digest)
        								.fingerprintAlgorithm("MD5")
        								.build();
        EnrollmentResult result = client.enroll("INBOUND_TLSzmcXc0IBDOoG".toCharArray());
        if (result.isPending() == false) {
        	System.out.println(result.getCertificates());
        } else {
        	ScheduledExecutorService exec = new ScheduledThreadPoolExecutor(1);
        	ScheduledFuture<EnrollmentResult> future = exec.schedule(result.getTask(), 3, TimeUnit.HOURS);
        	
        	System.out.println(result.getTask());
        }
        
    }
    
    @Ignore
    private static class DefaultTrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {

        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {

        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
    
    @Ignore
    private static class DefaultHostnameVerifier implements HostnameVerifier {
    	public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
}
