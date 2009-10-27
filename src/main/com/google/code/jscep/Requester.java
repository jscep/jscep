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

import com.google.code.jscep.content.ScepContentHandlerFactory;
import com.google.code.jscep.request.*;
import com.google.code.jscep.response.CaCapabilitiesResponse;
import com.google.code.jscep.response.CaCertificateResponse;
import com.google.code.jscep.response.CertRep;
import com.google.code.jscep.response.ScepResponse;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Requester {
    static {
        URLConnection.setContentHandlerFactory(new ScepContentHandlerFactory());
    }

    private final URL url;
    private final Proxy proxy;
    private String caIdentifier;

    public Requester(URL url) {
        this(url, Proxy.NO_PROXY);
    }

    public Requester(URL url, Proxy proxy) {
        this.url = url;
        this.proxy = proxy;
    }

    public void setCaIdentifier(String caIdentifier) {
        this.caIdentifier = caIdentifier;
    }

    public CaCapabilitiesResponse getCapabilities() throws IOException {
        ScepRequest req = new GetCACaps(caIdentifier);

        return (CaCapabilitiesResponse) sendRequest(req);
    }

    public List<X509Certificate> getCaCertificate() throws IOException {
        ScepRequest req = new GetCACert(caIdentifier);
        CaCertificateResponse res = (CaCertificateResponse) sendRequest(req);
        
        List<X509Certificate> certs = new ArrayList<X509Certificate>(2);
        certs.add(res.getCaCertificate());
        if (res.hasRaCertificate()) {
            certs.add(res.getRaCertificate());
        }

        return certs;
    }

    public ScepResponse getCrl(X509Certificate ca) throws IOException {
        Postable req = new GetCRL(ca);

        return sendRequest(req);
    }

    public CertRep enroll(KeyPair pair, X500Principal subject, char[] password) throws IOException {
        Postable req = new PkcsReq(getCaCertificate().get(0), subject, pair, password);

        return (CertRep) sendRequest(req);
    }

    private ScepResponse sendRequest(ScepRequest msg) throws IOException {
        return sendGetRequest(msg);
    }

    private ScepResponse sendRequest(Postable msg) throws IOException {
        return sendPostRequest(msg);
    }

    private ScepResponse sendGetRequest(ScepRequest msg) throws IOException {
        URL operation;
        if (msg.getMessage() == null) {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation());
        } else {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation() + "&message=" + msg.getMessage());
        }
        URLConnection conn = operation.openConnection(proxy);

        return (ScepResponse) conn.getContent();
    }

    private ScepResponse sendPostRequest(Postable msg) throws IOException {
        URL operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation());
        HttpURLConnection conn = (HttpURLConnection) operation.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        conn.getOutputStream().write((byte[]) msg.getMessage());

        return (ScepResponse) conn.getContent();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());


        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
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

        URL url = new URL("https://engtest81-2.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe");
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("nj.proxy.avaya.com", 8000));
//        Requester client = new Requester(url, proxy);
        Requester client = new Requester(url);
        client.setCaIdentifier("tmclientca");

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = gen.genKeyPair();

        X509Certificate ca = client.getCaCertificate().get(0);
        client.enroll(pair, new X500Principal("CN=david"), "foo".toCharArray());
    }
}
