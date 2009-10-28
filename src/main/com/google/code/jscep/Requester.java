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

import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import com.google.code.jscep.content.ScepContentHandlerFactory;
import com.google.code.jscep.request.*;
import com.google.code.jscep.request.PkiRequest;
import com.google.code.jscep.response.Capabilities;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.*;
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

    private Capabilities getCapabilities() throws IOException {
        Request req = new GetCACaps(caIdentifier);

        return (Capabilities) sendRequest(req);
    }

    private List<X509Certificate> getCaCertificate() throws IOException {
        Request req = new GetCACert(caIdentifier);
        
        return (List<X509Certificate>) sendRequest(req);
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

        CMSSignedData signedData = (CMSSignedData) sendRequest(req);
        SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        for (Object signer : signers) {
            SignerInformation signerInformation = (SignerInformation) signer;
            AttributeTable signedAttrs = signerInformation.getSignedAttributes();

            Attribute transIdAttr = signedAttrs.get(ScepObjectIdentifiers.transId);
            DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
            Attribute pkiStatusAttribute = signedAttrs.get(ScepObjectIdentifiers.pkiStatus);
            DERPrintableString pkiStatus = (DERPrintableString) pkiStatusAttribute.getAttrValues().getObjectAt(0);
            Attribute msgTypeAttribute = signedAttrs.get(ScepObjectIdentifiers.messageType);
            DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
            Attribute senderNoneAttribute = signedAttrs.get(ScepObjectIdentifiers.senderNonce);
            DEROctetString senderNonce = (DEROctetString) senderNoneAttribute.getAttrValues().getObjectAt(0);
            Attribute recipientNonceAttribute = signedAttrs.get(ScepObjectIdentifiers.recipientNonce);
            DEROctetString recipientNonce = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        }
        ContentInfo contentInfo = signedData.getContentInfo();

        return null;
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

    private Object sendRequest(Request msg) throws IOException {
        URL url = getUrl(msg.getOperation(), msg.getMessage());
        URLConnection conn = url.openConnection(proxy);
        System.out.println(url);

        return conn.getContent();
    }

    private Object sendRequest(PkiRequest msg) throws IOException {
        boolean usePost = getCapabilities().supportsPost();
        String op = msg.getOperation();
        URL url;
        if (usePost) {
            url = getUrl(op);
        } else {
            url = getUrl(op, msg.getMessage());
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        if (usePost) {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.addRequestProperty("Content-Length", Integer.toString(msg.getMessage().length));

            OutputStream stream = conn.getOutputStream();
            stream.write(msg.getMessage());
            stream.close();
        }

        return conn.getContent();
    }

    private URL getUrl(String op, Object message) throws MalformedURLException {
        if (message == null) {
            return new URL(getUrl(op).toExternalForm() + "&message=");
        } else {
            return new URL(getUrl(op).toExternalForm() + "&message=" + message);
        }
    }

    private URL getUrl(String op, byte[] msg) throws MalformedURLException, UnsupportedEncodingException {
        String encodedMsg = URLEncoder.encode(new String(Base64.encode(msg)), "UTF-8");
        
        return new URL(getUrl(op).toExternalForm() + "&message=" + encodedMsg);
    }

    private URL getUrl(String op) throws MalformedURLException {
        return new URL(url.toExternalForm() + "?operation=" + op);
    }
}
