/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep;

import com.google.code.jscep.content.ScepContentHandlerFactory;
import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.ScepRequest;
import com.google.code.jscep.response.CaCapabilitiesResponse;
import com.google.code.jscep.response.CaCertificateResponse;
import com.google.code.jscep.response.ScepResponse;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
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

        CaCertificateResponse res = client.getCaCertificate("tmdefaultca");
        System.out.println(res.getCaCertificate());
        if (res.hasRaCertificate()) {
            System.out.println(res.getRaCertificate());
        }
    }
}
