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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.GetCRL;
import com.google.code.jscep.request.GetCert;
import com.google.code.jscep.request.GetNextCaCert;
import com.google.code.jscep.request.PkiOperation;
import com.google.code.jscep.request.Request;
import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.TransactionFactory;
import com.google.code.jscep.transport.Transport;

/**
 * SCEP Client
 */
public class Requester {
    private URL url;						// Required
    private byte[] fingerprint;				// Required
    private String fingerprintAlgorithm;	// Required
    private Proxy proxy;					// Optional
    private String identifier;				// Optional
    private KeyPair keyPair;				// Optional
    private X509Certificate identity;		// Optional
    private X500Principal subject;			// Optional
    
    private X509Certificate ca;

    private Requester(Builder builder) throws IllegalStateException {
    	url = builder.url;
    	proxy = builder.proxy;
    	fingerprint = builder.fingerprint;
    	identifier = builder.identifier;
    	keyPair = builder.keyPair;
    	identity = builder.identity;
    	subject = builder.subject;
    	fingerprintAlgorithm = builder.fingerprintAlgorithm;
    	
    	if (url == null) {
    		throw new IllegalStateException("URL must not be null.");
    	}
    	// 2.1.2.1
    	if (fingerprint == null) {
    		throw new IllegalStateException("Digest must not be null.");
    	}
    	// Must have only one way of obtaining an identity.
    	if (identity == null && subject == null) {
    		throw new IllegalStateException("Need Identity OR Subject");
    	}
    	if (identity != null && subject != null) {
    		throw new IllegalStateException("Need Identity OR Subject");
    	}
    	
    	// Set Defaults
    	if (fingerprintAlgorithm == null) {
    		fingerprintAlgorithm = "MD5";
    	}
    	if (proxy == null) {
    		proxy = Proxy.NO_PROXY;
    	}
    	if (keyPair == null) {
    		keyPair = createKeyPair();		
    	}
    	if (identity == null) {
    		identity = createCertificate();
    	}
    	
		// If we're replacing a certificate, we must have the same key pair.
		if (identity.getPublicKey().equals(keyPair.getPublic()) == false) {
			throw new IllegalStateException("Public Key Mismatch");
		}
		List<String> algorithms = new LinkedList<String>();
		algorithms.add("MD5");
		algorithms.add("SHA-1");
		algorithms.add("SHA-256");
		algorithms.add("SHA-512");
		if (algorithms.contains(fingerprintAlgorithm) == false) {
			throw new IllegalStateException(fingerprintAlgorithm + " is not a valid fingerprint algorithm");
		}
    }
    
    private void debug(String msg) {
    	System.out.println(msg);
    }
    
    private KeyPair createKeyPair() {
    	debug("Creating RSA Key Pair");
    	
    	try {
			return KeyPairGenerator.getInstance("RSA").genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
    }
    
    private X509Certificate createCertificate() {
    	debug("Creating Self-Signed Certificate for " + subject);
    	
    	// TODO: BC Dependency
    	Calendar cal = Calendar.getInstance();
    	cal.add(Calendar.DATE, -1);
    	Date notBefore = cal.getTime();
    	cal.add(Calendar.DATE, 2);
    	Date notAfter = cal.getTime();
    	X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
    	gen.setIssuerDN(subject);
    	gen.setNotBefore(notBefore);
    	gen.setNotAfter(notAfter);
    	gen.setPublicKey(keyPair.getPublic());
    	gen.setSerialNumber(BigInteger.ONE);
    	// TODO: Don't hardcode SHA1withRSA
    	gen.setSignatureAlgorithm("SHA1withRSA");
    	gen.setSubjectDN(subject);
    	try {
			return gen.generate(keyPair.getPrivate());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
    }
    
    private Transaction createTransaction() throws IOException {
    	return TransactionFactory.createTransaction(createTransport(), ca, identity, keyPair, fingerprintAlgorithm);
    }
    
    private Transport createTransport() throws IOException {
    	if (getCapabilities().supportsPost()) {
    		return Transport.createTransport(Transport.Method.POST, url, proxy);
    	} else {
    		return Transport.createTransport(Transport.Method.GET, url, proxy);
    	}
    }
    
    /**
     * Retrieve the generated {@link KeyPair}.
     * 
     * @return the key pair.
     */
    public KeyPair getKeyPair() {
    	return keyPair;
    }

    private Capabilities getCapabilities() throws IOException {
        Request req = new GetCACaps(identifier);
        Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);

        return (Capabilities) trans.sendMessage(req);
    }

    private List<X509Certificate> getCaCertificate() throws IOException {
        Request req = new GetCACert(identifier);
        Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
        
        return (List<X509Certificate>) trans.sendMessage(req);
    }
    
    public List<X509Certificate> getNextCA() throws IOException {
    	Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
    	Request req = new GetNextCaCert(identifier);
    	
    	return (List<X509Certificate>) trans.sendMessage(req);
    }

    private void updateCertificates() throws IOException, CertificateException, ScepException {
    	List<X509Certificate> certs = getCaCertificate();

        ca = certs.get(0);
        
        MessageDigest md;
		try {
			md = MessageDigest.getInstance(fingerprintAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
        if (Arrays.equals(fingerprint, md.digest(ca.getEncoded())) == false) {
        	throw new ScepException("CA Fingerprint Error");
        }
    }

    /**
     * Retrieves the certificate revocation list for the current CA.
     * 
     * @return the certificate revocation list.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException
     * @throws GeneralSecurityException
     * @throws UnsupportedCallbackException 
     * @throws RequestFailureException 
     */
    public List<X509CRL> getCrl() throws IOException, ScepException, GeneralSecurityException, UnsupportedCallbackException, RequestPendingException, RequestFailureException {
        updateCertificates();
        if (supportsDistributionPoints()) {
        	return null;
        } else {
	        // PKI Operation
	        PkiOperation req = new GetCRL(ca.getIssuerX500Principal(), ca.getSerialNumber());
	        CertStore store = createTransaction().performOperation(req);
	        
	        return getCRLs(store.getCRLs(null));
        }
    }
    
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.2.4
     */
    private boolean supportsDistributionPoints() {
    	return false;
    }

    /**
     * Enrolls an identity into a PKI domain.
     * 
     * @param password the enrollment password.
     * @return the enrolled certificate.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException
     * @throws GeneralSecurityException
     * @throws UnsupportedCallbackException 
     */
    public EnrollmentResult enroll(char[] password) throws Exception {
        updateCertificates();
        
        return new InitialEnrollmentTask(createTransport(), ca, keyPair, identity, password, fingerprintAlgorithm).call();
    }

    /**
     * Retrieves the certificate corresponding to the given serial number.
     * 
     * @param serial the serial number of the certificate.
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException
     * @throws GeneralSecurityException
     * @throws UnsupportedCallbackException 
     * @throws RequestPendingException 
     * @throws RequestFailureException 
     */
    public X509Certificate getCert(BigInteger serial) throws IOException, ScepException, GeneralSecurityException, UnsupportedCallbackException, RequestPendingException, RequestFailureException {
        updateCertificates();
        // PKI Operation
        PkiOperation req = new GetCert(ca.getIssuerX500Principal(), serial);
        CertStore store = createTransaction().performOperation(req);

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
    
    /**
     * Builder for obtaining an instance of {@link Requester}.
     */
    public static class Builder {
    	private URL url;
    	private Proxy proxy;
    	private String identifier;
    	private KeyPair keyPair;
    	private X509Certificate identity;
    	private X500Principal subject;
    	private byte[] fingerprint;
    	private String fingerprintAlgorithm;
    	
    	public Builder(URL url) {
    		this.url = url;
    	}
    	
    	public Builder proxy(Proxy proxy) {
    		this.proxy = proxy;
    		
    		return this;
    	}
    	
    	public Builder identifier(String identifier) {
    		this.identifier = identifier;
    		
    		return this;
    	}
    	
    	public Builder keyPair(KeyPair keyPair) {
    		this.keyPair = keyPair;
    		
    		return this;
    	}
    	
    	public Builder subject(X500Principal subject) {
    		this.subject = subject;
    		
    		return this;
    	}
    	
    	public Builder identity(X509Certificate identity) {
    		this.identity = identity;
    		
    		return this;
    	}
    	
    	/**
    	 * The message digest of the CA certificate.
    	 * 
    	 * @param fingerprint the digest.
    	 * @return this builder.
    	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
    	 */
    	public Builder fingerprint(byte[] fingerprint) {
    		this.fingerprint = fingerprint;
    		
    		return this;
    	}
    	
    	/**
    	 * One of <tt>MD5</tt>, <tt>SHA-1</tt>, <tt>SHA-256</tt> or <tt>SHA-512</tt>.  Defaults to MD5.
    	 * 
    	 * @param fingerprintAlgorithm the hash algorithm for encoding the certificate.
    	 * @return this builder.
    	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
    	 */
    	public Builder fingerprintAlgorithm(String fingerprintAlgorithm) {
    		this.fingerprintAlgorithm = fingerprintAlgorithm;
    		
    		return this;
    	}
    	
    	public Requester build() throws IllegalStateException {
    		return new Requester(this);
    	}
    }
}
