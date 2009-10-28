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
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.response.CaCapabilitiesResponse;
import com.google.code.jscep.response.CaCertificateResponse;
import com.google.code.jscep.response.CertRep;
import com.google.code.jscep.response.ScepResponse;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Requester {
    static {
        URLConnection.setContentHandlerFactory(new ScepContentHandlerFactory());
    }

    private final URL url;
    private final Proxy proxy;
    private String caIdentifier;
    private X509Certificate existing;
    private X509Certificate ca;
    private X509Certificate ra;
    private KeyPair keyPair;

    public Requester(URL url) {
        this(url, Proxy.NO_PROXY);
    }

    public Requester(URL url, Proxy proxy) {
        this.url = url;
        this.proxy = proxy;
    }

    public void initialize(X509Certificate ca) {
        this.ca = ca;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            keyPair = gen.generateKeyPair();
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }

    public void setCaIdentifier(String caIdentifier) {
        this.caIdentifier = caIdentifier;
    }

    private CaCapabilitiesResponse getCapabilities() throws IOException {
        ScepRequest req = new GetCACaps(caIdentifier);

        return (CaCapabilitiesResponse) sendRequest(req);
    }

    private List<X509Certificate> getCaCertificate() throws IOException {
        ScepRequest req = new GetCACert(caIdentifier);
        CaCertificateResponse res = (CaCertificateResponse) sendRequest(req);
        
        List<X509Certificate> certs = new ArrayList<X509Certificate>(2);
        certs.add(res.getCaCertificate());
        if (res.hasRaCertificate()) {
            certs.add(res.getRaCertificate());
        }

        return certs;
    }

    private void updateCertificates() throws IOException {
        List<X509Certificate> certs = getCaCertificate();

        ca = certs.get(0);
        if (certs.size() == 2) {
            ra = certs.get(1);
        }
    }

    public X509CRL getCrl() throws IOException {
        updateCertificates();
        // PKI Operation
        PkiRequest req = new GetCRL(ca, keyPair);

        CertRep res = (CertRep) sendRequest(req);
        try {
            CertStore store = res.getCRL();
            X509CRLSelector selector = new X509CRLSelector();
            selector.addIssuer(ca.getIssuerX500Principal());
            Collection<? extends CRL> crls = store.getCRLs(selector);

            if (crls.size() > 0) {
                return (X509CRL) crls.iterator().next();
            } else {
                return null;
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public void setExistingCertificate(X509Certificate cert) {
        existing = cert;
    }

    public List<X509Certificate> enroll(X500Principal subject, CallbackHandler cbh) throws IOException, UnsupportedCallbackException {
        updateCertificates();
        // PKI Operation
        PasswordCallback cb = new PasswordCallback("Password", false);
        cbh.handle(new Callback[] {cb});
        PkiRequest req = new PkcsReq(ca, keyPair, subject, cb.getPassword());
        cb.clearPassword();

        sendRequest(req);

        return null;
    }

    public List<X509Certificate> getCertInitial(X500Principal subject) throws IOException {
        updateCertificates();
        // PKI Operation
        PkiRequest req = new GetCertInitial(ca, keyPair, subject);

        sendRequest(req);

        return null;
    }

    public List<X509Certificate> getCert(BigInteger serialNumber) throws IOException {
        updateCertificates();
        // PKI Operation
        PkiRequest req = new GetCert(ca, keyPair, serialNumber);

        sendRequest(req);

        return null;
    }

    private ScepResponse sendRequest(ScepRequest msg) throws IOException {
        return sendGetRequest(msg);
    }

    private ScepResponse sendRequest(PkiRequest msg) throws IOException {
        if (getCapabilities().supportsPost()) {
            return sendPostRequest(msg);
        } else {
            return sendGetRequest(msg);
        }
    }

    private ScepResponse sendGetRequest(ScepRequest msg) throws IOException {
        URL operation;
        if (msg.getMessage() == null) {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation());
        } else {
            operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation() + "&message=" + URLEncoder.encode(msg.getMessage().toString(), "UTF-8"));
        }
        URLConnection conn = operation.openConnection(proxy);

        return (ScepResponse) conn.getContent();
    }

    private ScepResponse sendPostRequest(PkiRequest msg) throws IOException {
        byte[] bytes = msg.getMessage().getBytes();

        URL operation = new URL(url.toExternalForm() + "?operation=" + msg.getOperation());
        HttpURLConnection conn = (HttpURLConnection) operation.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.addRequestProperty("Content-Length", Integer.toString(bytes.length));

        OutputStream os = conn.getOutputStream();
        os.write(msg.getMessage().getBytes());
        os.close();

        return (ScepResponse) conn.getContent();
    }
}
