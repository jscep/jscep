/*
 * Copyright (c) 2009-2010 David Grant
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

package com.google.code.jscep.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Proxy;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import com.google.code.jscep.PKIOperationFailureException;
import com.google.code.jscep.operations.GetCRL;
import com.google.code.jscep.operations.GetCert;
import com.google.code.jscep.operations.PKCSReq;
import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.GetNextCACert;
import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.TransactionFactory;
import com.google.code.jscep.transport.Transport;
import com.google.code.jscep.util.LoggingUtil;
import com.google.code.jscep.x509.X509Util;

/**
 * SCEP Client
 */
public class Client {
	private static Logger LOGGER = LoggingUtil.getLogger(Client.class);
    private URL url;						// Required
    private byte[] caDigest;				// Required
    private String digestAlgorithm;			// Optional
    private Proxy proxy;					// Optional
    private String caIdentifier;			// Optional
    private KeyPair keyPair;				// Optional
    private X509Certificate identity;		// Optional
    private X500Principal subject;
    private X509Certificate ca;
    
    private Client(Builder builder) throws IllegalStateException {
    	url = builder.url;
    	proxy = builder.proxy;
    	caDigest = builder.caDigest;
    	digestAlgorithm = builder.digestAlgorithm;
    	caIdentifier = builder.caIdentifier;
    	keyPair = builder.keyPair;
    	identity = builder.identity;
    	subject = builder.subject;
    	ca = builder.ca;
    	
    	// See http://tools.ietf.org/html/draft-nourse-scep-19#section-5.1
    	if (isValid(url) == false) {
    		throw new IllegalStateException("Invalid URL");
    	}
    	// See http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
    	if (ca == null && caDigest == null) {
    		throw new IllegalStateException("Need CA OR CA Digest.");
    	}
    	if (ca != null && caDigest != null) {
    		throw new IllegalStateException("Need CA OR CA Digest.");
    	}
    	// Must have only one way of obtaining an identity.
    	if (identity == null && subject == null) {
    		throw new IllegalStateException("Need Identity OR Subject");
    	}
    	if (identity != null && subject != null) {
    		throw new IllegalStateException("Need Identity OR Subject");
    	}
    	
    	// Set Defaults
    	if (digestAlgorithm == null) {
    		digestAlgorithm = "MD5";
    	}
    	if (proxy == null) {
    		proxy = Proxy.NO_PROXY;
    	}
    	if (keyPair == null) {
    		keyPair = createKeyPair();		
    	}
    	if (isValid(keyPair) == false) {
    		throw new IllegalStateException("Invalid KeyPair");
    	}
    	if (identity == null) {
    		identity = createCertificate(subject);
    	}
    	
		// If we're replacing a certificate, we must have the same key pair.
		if (identity.getPublicKey().equals(keyPair.getPublic()) == false) {
			throw new IllegalStateException("Public Key Mismatch");
		}
		
		// Check renewal
		if (subject == null) {
			if (X509Util.isSelfSigned(identity) == false) {
				if (identity.getIssuerX500Principal().equals(ca.getSubjectX500Principal())) {
					LOGGER.fine("Certificate is signed by CA, so this is a renewal.");
				} else {
					LOGGER.fine("Certificate is signed by another CA, bit this is still a renewal.");
				}
				try {
					LOGGER.fine("Checking if the CA supports certificate renewal...");
					if (getCapabilities().isRenewalSupported() == false) {
						throw new IllegalStateException("Your CA does not support renewal");
					}
				} catch (IOException e) {
					throw new IllegalStateException("Your CA does not support renewal");
				}
			} else {
				LOGGER.fine("Certificate is self-signed.  This is not a renewal.");
			}
		}
    }

    
    private boolean isValid(KeyPair keyPair) {
    	PrivateKey pri = keyPair.getPrivate();
    	PublicKey pub = keyPair.getPublic();
    	
    	return pri.getAlgorithm().equals("RSA") && pub.getAlgorithm().equals("RSA");
    }
    
    private boolean isValid(URL url) {
    	if (url == null) {
    		return false;
    	}
    	if (url.getProtocol().matches("^https?$") == false) {
    		return false;
    	}
    	if (url.getPath().endsWith("pkiclient.exe") == false) {
    		return false;
    	}
    	if (url.getRef() != null) {
    		return false;
    	}
    	if (url.getQuery() != null) {
    		return false;
    	}
    	return true;
    }
    
    private KeyPair createKeyPair() {
    	LOGGER.fine("Creating RSA Key Pair");
    	
    	try {
			return KeyPairGenerator.getInstance("RSA").genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
    }
    
    private X509Certificate createCertificate(X500Principal subject) {
    	LOGGER.fine("Creating Self-Signed Certificate for " + subject);
    	
    	try {
    		return X509Util.createEphemeralCertificate(subject, keyPair);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
    }
    
    private Transaction createTransaction() throws IOException {
    	return TransactionFactory.createTransaction(createTransport(), getRecipientCertificate(), identity, keyPair, getCapabilities().getStrongestMessageDigest());
    }
    
    private Transport createTransport() throws IOException {
    	LOGGER.entering(getClass().getName(), "createTransport");
    	
    	final Transport t;
    	if (getCapabilities().isPostSupported()) {
    		t = Transport.createTransport(Transport.Method.POST, url, proxy);
    	} else {
    		t = Transport.createTransport(Transport.Method.GET, url, proxy);
    	}
    	
    	LOGGER.exiting(getClass().getName(), "createTransport", t);
    	
    	return t;
    }
    
    /**
     * Retrieve the generated {@link KeyPair}.
     * 
     * @return the key pair.
     */
    public KeyPair getKeyPair() {
    	return keyPair;
    }

    /**
     * Retrieves the set of SCEP capabilities from the CA.
     * 
     * @return the capabilities of the server.
     * @throws IOException if any I/O error occurs.
     */
    public Capabilities getCapabilities() throws IOException {
    	final GetCACaps req = new GetCACaps(caIdentifier);
        final Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);

        return trans.sendMessage(req);
    }

    /**
     * Retrieves the CA certificate.
     * <p>
     * If the CA is using an RA, the RA certificate will also
     * be present in the returned list.
     * 
     * @return the list of certificates.
     * @throws IOException if any I/O error occurs.
     */
    public List<X509Certificate> getCaCertificate() throws IOException {
    	final GetCACert req = new GetCACert(caIdentifier);
        final Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
        
        return trans.sendMessage(req);
    }
    
    /**
     * Retrieves the "rollover" certificate to be used by the CA.
     * <p>
     * If the CA is using an RA, the RA certificate will be present
     * in the returned list.
     * 
     * @return the list of certificates.
     * @throws IOException if any I/O error occurs.
     */
    public List<X509Certificate> getNextCA() throws IOException {
    	if (getCapabilities().isNextCASupported() == false) {
    		throw new UnsupportedOperationException();
    	}
    	final X509Certificate issuer = retrieveCA();
    	
    	final Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
    	final GetNextCACert req = new GetNextCACert(issuer, caIdentifier);
    	
    	return trans.sendMessage(req);
    }
    
    private X509Certificate retrieveCA() throws IOException {
    	final List<X509Certificate> certs = getCaCertificate();
    	
    	return selectCA(certs);
    }
    
    private X509Certificate getRecipientCertificate() throws IOException {
    	final List<X509Certificate> certs = getCaCertificate();
    	// The CA or RA
    	return selectRecipient(certs);
    }
    
    private X509Certificate selectRecipient(List<X509Certificate> certs) {
    	int numCerts = certs.size();
    	if (numCerts == 2) {
    		final X509Certificate ca = selectCA(certs);
    		// The RA certificate is the other one.
    		int caIndex = certs.indexOf(ca);
    		int raIndex = 1 - caIndex;
    		
    		return certs.get(raIndex);
    	} else if (numCerts == 1) {
    		return certs.get(0);
    	} else {
    		// We've either got NO certificates here, or more than 2.
    		// Whatever the case, the server is in error. 
    		throw new IllegalStateException();
    	}
    }
    
    private X509Certificate selectCA(List<X509Certificate> certs) {
    	if (certs.size() == 1) {
    		return certs.get(0);
    	}
    	// We don't know the order here, but we know the RA certificate MUST
		// have been issued by the CA certificate.
		final X509Certificate first = certs.get(0);
		final X509Certificate second = certs.get(1);
		try {
			// First, let's check if the second certificate is the CA.
			first.verify(second.getPublicKey());
			
			return second;
		} catch (InvalidKeyException e) {
			// Do nothing here, as we're going to try the reverse now.
		} catch (Exception e) {
			// Something else went wrong.
			throw new RuntimeException(e);
		}
		try {
			// OK, that didn't work out, so let's try the first instead.
			second.verify(first.getPublicKey());
			
			return first;
		} catch (Exception e) {
			// Neither certificate was the CA.
			// TODO
			throw new RuntimeException(e);
		}
    }
    
    /**
     * Retrieves the certificate revocation list for the current CA.
     * 
     * @return the certificate revocation list.
     * @throws IOException if any I/O error occurs.
     * @throws PKIOperationFailureException 
     */
    public List<X509CRL> getCrl() throws IOException, PKIOperationFailureException {
        final X509Certificate ca = retrieveCA();
        
        if (supportsDistributionPoints()) {
        	return null;
        } else {
	        // PKI Operation
	        final GetCRL req = new GetCRL(ca.getIssuerX500Principal(), ca.getSerialNumber());
	        final CertStore store = createTransaction().performOperation(req);
	        
	        try {
				return getCRLs(store.getCRLs(null));
			} catch (CertStoreException e) {
				throw new IOException(e);
			}
        }
    }
    
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.2.4
     */
    private boolean supportsDistributionPoints() {
    	// TODO Implement CDP
    	return false;
    }

    /**
     * Enrolls an identity into a PKI domain.
     * <p>
     * If the CA uses a manual process, this method will block until the
     * CA administrator either accepts or rejects the request.
     * <p>
     * 
     * @param password the enrollment password.
     * @param interval the period to wait between polls.
     * @return the enrolled certificate.
     * @throws IOException if any I/O error occurs.
     * @throws PKIOperationFailureException 
     */
    public List<X509Certificate> enroll(char[] password, long interval) throws IOException, PKIOperationFailureException {
    	LOGGER.entering(getClass().getName(), "enroll", new Object[] {password, interval});
    	
    	final PKCSReq req = new PKCSReq(keyPair, identity, digestAlgorithm, password);
    	final CertStore store = createTransaction().performOperation(req, interval);
    	final List<X509Certificate> certs;
		try {
			certs = getCertificates(store.getCertificates(null));
		} catch (CertStoreException e) {
			// TODO
			throw new RuntimeException(e);
		}
    	
    	LOGGER.exiting(getClass().getName(), "enroll", certs);
    	return certs;
    }

    /**
     * Retrieves the certificate corresponding to the given serial number.
     * 
     * @param serial the serial number of the certificate.
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws PKIOperationFailureException 
     */
    public X509Certificate getCert(BigInteger serial) throws IOException, PKIOperationFailureException {
    	final X509Certificate ca = retrieveCA();

        final GetCert req = new GetCert(ca.getIssuerX500Principal(), serial);
        final CertStore store = createTransaction().performOperation(req);

        try {
			return getCertificates(store.getCertificates(null)).get(0);
		} catch (CertStoreException e) {
			throw new RuntimeException(e);
		}
    }
    
    private List<X509Certificate> getCertificates(Collection<? extends Certificate> certs) {
    	final List<X509Certificate> x509 = new ArrayList<X509Certificate>();
    	
    	for (Certificate cert : certs) {
    		x509.add((X509Certificate) cert);
    	}
    	
    	return x509;
    }
    
    private List<X509CRL> getCRLs(Collection<? extends CRL> crls) {
    	final List<X509CRL> x509 = new ArrayList<X509CRL>();
        
        for (CRL crl : crls) {
        	x509.add((X509CRL) crl);
        }
        
        return x509;
    }
    
    /**
     * See Effective Java, Item 2
     * 
     * @author David Grant
     */
    public static class Builder {
    	private URL url;
    	private Proxy proxy = Proxy.NO_PROXY;
    	private byte[] caDigest;
    	private String digestAlgorithm;
    	private String caIdentifier;
    	private X500Principal subject;
    	private X509Certificate identity;
    	private KeyPair keyPair;
    	private X509Certificate ca;
    	
    	public Builder url(URL url) {
    		this.url = url;
    		
    		return this;
    	}
    	
    	public Builder proxy(Proxy proxy) {
    		this.proxy = proxy;
    		
    		return this;
    	}
    	
    	public Builder ca(X509Certificate ca) {
    		this.ca = ca;
    		
    		return this;
    	}
    	
    	public Builder caDigest(byte[] caDigest, String digestAlgorithm) {
    		this.caDigest = caDigest;
    		this.digestAlgorithm = digestAlgorithm;
    		
    		return this;
    	}
    	
    	public Builder caIdentifier(String caIdentifier) {
    		this.caIdentifier = caIdentifier;
    		
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
    	
    	public Builder keyPair(KeyPair keyPair) {
    		this.keyPair = keyPair;
    		
    		return this;
    	}
    	
    	public Client build() throws IllegalStateException {
    		return new Client(this);
    	}
    }
}
