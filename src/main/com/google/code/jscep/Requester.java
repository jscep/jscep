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
import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.ScepRequest;
import com.google.code.jscep.response.CaCapabilitiesResponse;
import com.google.code.jscep.response.CaCertificateResponse;
import com.google.code.jscep.response.ScepResponse;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

import javax.crypto.KeyGenerator;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

public class Requester {
    static {
        URLConnection.setContentHandlerFactory(new ScepContentHandlerFactory());
    }

    private final URL url;
    private final Proxy proxy;

    public Requester(URL url) {
        this(url, Proxy.NO_PROXY);
    }

    public Requester(URL url, Proxy proxy) {
        this.url = url;
        this.proxy = proxy;
    }

    public CaCapabilitiesResponse getCapabilities() throws IOException {
        return getCapabilities(null);
    }

    public CaCapabilitiesResponse getCapabilities(String caIdentifer) throws IOException {
        ScepRequest req = new GetCACaps(caIdentifer);

        return (CaCapabilitiesResponse) sendRequest(req);
    }

    public CaCertificateResponse getCaCertificate() throws IOException {
        return getCaCertificate(null);
    }

    public CaCertificateResponse getCaCertificate(String caIdentifier) throws IOException {
        ScepRequest req = new GetCACert(caIdentifier);

        return (CaCertificateResponse) sendRequest(req); 
    }

    private ScepResponse sendRequest(ScepRequest msg) throws IOException {

        URL operation;
        if (msg.getMessage() == null) {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation());
        } else {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation() + "&message=" + msg.getMessage());
        }
        HttpURLConnection conn = (HttpURLConnection) operation.openConnection(proxy);
        conn.setRequestMethod("GET");

        return (ScepResponse) conn.getContent();
    }

    public static void main(String[] args) throws Exception {

        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {

            }
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                
            }
            public X509Certificate[] getAcceptedIssuers() {
                   return null;
            }
        }}, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());

        URL url = new URL("https://engtest76-3.eu.ubiquity.net/ejbca/publicweb/apply/scep/pkiclient.exe");
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("nj.proxy.avaya.com", 8000));
//        Requester client = new Requester(url, proxy);
        Requester client = new Requester(url);
        System.out.println(client.getCapabilities("tmdefaultca"));

        CaCertificateResponse res = client.getCaCertificate("tmdefaultca");
        System.out.println(res.getCaCertificate());
        if (res.hasRaCertificate()) {
            System.out.println(res.getRaCertificate());
        }

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = gen.genKeyPair();
        AlgorithmIdentifier id = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
        SubjectPublicKeyInfo pki = new SubjectPublicKeyInfo(id, pair.getPublic().getEncoded());
        System.out.println(pki);

        X500Principal x500 = new X500Principal("CN=foo");
        X509Principal x509 = new X509Principal(x500.getEncoded());

        CertificationRequestInfo reqInfo = new CertificationRequestInfo(x509, pki, null);

        AlgorithmIdentifier certReqAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption);
        CertificationRequest req = new CertificationRequest(reqInfo, certReqAlg, null);

        System.out.println(req);

        // org.bouncycastle.cms.CMSSignedData
        // org.bouncycastle.cms.CMSEnvelopedData
        // PKCS10CertificationRequest
    }
}
