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

import java.io.IOException;
import java.math.BigInteger;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import com.google.code.jscep.content.ScepContentHandlerFactory;
import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.GetCRL;
import com.google.code.jscep.request.GetCert;
import com.google.code.jscep.request.GetCertInitial;
import com.google.code.jscep.request.PkcsReq;
import com.google.code.jscep.request.PkiOperation;
import com.google.code.jscep.request.Request;
import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.transport.Transport;

public class Requester {
    static {
        URLConnection.setContentHandlerFactory(new ScepContentHandlerFactory());
    }

    private final URL url;
    private final Proxy proxy;
    private String caIdentifier;
    private X509Certificate ca;
    private final KeyPair keyPair;
    private Transaction transaction;
    
    public Requester(URL url) {
    	this(null, url, Proxy.NO_PROXY);
    }

    public Requester(KeyPair keyPair, URL url) {
        this(keyPair, url, Proxy.NO_PROXY);
    }
    
    public Requester(URL url, Proxy proxy) {
    	this(null, url, proxy);
    }

    public Requester(KeyPair keyPair, URL url, Proxy proxy) {
        this.url = url;
        this.proxy = proxy;
        
        if (keyPair == null) {
        	try {
				this.keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
    	} else {
    		this.keyPair = keyPair;
		}
    }
    
    public KeyPair getKeyPair() {
    	return keyPair;
    }

    public void setCaIdentifier(String caIdentifier) {
        this.caIdentifier = caIdentifier;
    }

    private Capabilities getCapabilities() throws IOException {
        Request req = new GetCACaps(caIdentifier);
        Transport trans = Transport.createTransport("GET", url, proxy);

        return (Capabilities) trans.sendMessage(req);
    }

    private X509Certificate[] getCaCertificate() throws IOException {
        Request req = new GetCACert(caIdentifier);
        Transport trans = Transport.createTransport("GET", url, proxy);
        
        return (X509Certificate[]) trans.sendMessage(req);
    }

    private void updateCertificates() throws IOException {
        X509Certificate[] certs = getCaCertificate();

        ca = certs[0];
    }
    
    private Transport getTransport() throws IOException {
    	if (getCapabilities().supportsPost()) {
    		return Transport.createTransport("POST", url, proxy);
    	} else {
    		return Transport.createTransport("GET", url, proxy);
    	}
    }
    
    public Transaction getCurrentTransaction() {
    	return transaction;
    }
    
    private Transaction getTransaction(X509Certificate cert, KeyPair keyPair) throws IOException {
    	return TransactionFactory.createTransaction(getTransport(), cert, keyPair);
    }

    public X509CRL getCrl() throws IOException, ScepException, GeneralSecurityException {
        updateCertificates();
        // PKI Operation
        PkiOperation req = new GetCRL(ca.getIssuerX500Principal(), ca.getSerialNumber());
        CertStore store = getTransaction(ca, keyPair).performOperation(req);
        
        List<X509CRL> crls = getCRLs(store.getCRLs(null));
        if (crls.size() > 0) {
        	return crls.get(0);
        } else {
        	return null;
        }
    }

    public X509Certificate enroll(X500Principal subject, char[] password) throws IOException, UnsupportedCallbackException, ScepException, GeneralSecurityException {
        updateCertificates();
        // PKI Operation
        PkiOperation req = new PkcsReq(keyPair, subject, password);
        CertStore store = getTransaction(ca, keyPair).performOperation(req);

        return getCertificates(store.getCertificates(null)).get(0);
    }
    
    public X509Certificate renew(X509Certificate existing, char[] password) throws IOException, UnsupportedCallbackException, ScepException, GeneralSecurityException {
    	if (getCapabilities().supportsRenewal() == false) {
    		throw new ScepException("Renewal Not Supported");
    	}
        updateCertificates();
        // PKI Operation
        PkiOperation req = new PkcsReq(keyPair, existing.getSubjectX500Principal(), password);
        CertStore store = getTransaction(ca, keyPair).performOperation(req);

        return getCertificates(store.getCertificates(null)).get(0);
    }

    public X509Certificate getCertInitial(X500Principal subject) throws IOException, ScepException, GeneralSecurityException {
        updateCertificates();
        // PKI Operation
        PkiOperation req = new GetCertInitial(ca.getIssuerX500Principal(), subject);
        CertStore store = getTransaction(ca, keyPair).performOperation(req);

        return getCertificates(store.getCertificates(null)).get(0);
    }

    public X509Certificate getCert(BigInteger serial) throws IOException, ScepException, GeneralSecurityException {
        updateCertificates();
        // PKI Operation
        PkiOperation req = new GetCert(ca.getIssuerX500Principal(), serial);
        CertStore store = getTransaction(ca, keyPair).performOperation(req);

        return getCertificates(store.getCertificates(null)).get(0);
    }
    
    private List<X509Certificate> getCertificates(Collection<? extends Certificate> certs) {
    	List<X509Certificate> x509 = new ArrayList<X509Certificate>();
    	
    	for (Certificate cert : certs) {
    		x509.add((X509Certificate) cert);
    	}
    	
    	return x509;
    }
    
    private List<X509CRL> getCRLs(Collection<? extends CRL> crls) {
    	List<X509CRL> x509 = new ArrayList<X509CRL>();
        
        for (CRL crl : crls) {
        	x509.add((X509CRL) crl);
        }
        
        return x509;
    }
}
