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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import com.google.code.jscep.FingerprintVerificationCallback;
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

/**
 * This class represents a SCEP client, or Requester.
 */
public class Client {
	private static Logger LOGGER = LoggingUtil.getLogger(Client.class);
	private Set<X509Certificate> verified = new HashSet<X509Certificate>(1);
    private URL url;						// Required
    private Proxy proxy;					// Optional
    private String caIdentifier;			// Optional
    private KeyPair keyPair;				// Optional
    private X509Certificate identity;		// Optional
    
    private byte[] fingerprint;				// Required
    private String hashAlgorithm;			// Required
    // OR
    private CallbackHandler callbackHandler; // Optional
    
    private Client(Builder builder) throws IllegalStateException {
    	url = builder.url;
    	proxy = builder.proxy;
    	caIdentifier = builder.caIdentifier;
    	// This is used for communicating with the SCEP server.  It SHOULD
    	// NOT necessarily correspond to what we're going to enroll.
    	keyPair = builder.keyPair;
    	identity = builder.identity;
    	// or we can use the fingerprints (pre-provisioning)
    	fingerprint = builder.fingerprint;
    	hashAlgorithm = builder.hashAlgorithm;
    	// Used to present to the end-user (out-of-band)
    	callbackHandler = builder.callbackHandler;
    	
    	// Offering the use of multiple hash algorithms for the
    	// certificate fingerprint just makes things more complicated for
    	// pre-provisioning.  Perhaps we should settle on a definite hash?

    	if (callbackHandler != null) {
    		// Manual Authorization
    	} else {
    		// Automatic Authorization
    		callbackHandler = new FingerprintCallbackHandler(fingerprint, hashAlgorithm);
    	}
    	
    	// See http://tools.ietf.org/html/draft-nourse-scep-19#section-5.1
    	if (isValid(url) == false) {
    		throw new IllegalStateException("Invalid URL");
    	}
    	
    	if (proxy == null) {
    		proxy = Proxy.NO_PROXY;
    	}

    	if (isValid(keyPair) == false) {
    		throw new IllegalStateException("Invalid KeyPair");
    	}
    	
		// If we're replacing a certificate, we must have the same key pair.
		if (identity.getPublicKey().equals(keyPair.getPublic()) == false) {
			throw new IllegalStateException("Public Key Mismatch");
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
    	LOGGER.entering(getClass().getName(), "getCaCertificate");
    	final GetCACert req = new GetCACert(caIdentifier);
        final Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
        
        final List<X509Certificate> certs = trans.sendMessage(req);
        verifyCA(selectCA(certs));
        
        LOGGER.exiting(getClass().getName(), "getCaCertificate", certs);
        return certs;
    }
    
    private byte[] createFingerprint(X509Certificate cert, String hashAlgorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
    	final MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
    	return md.digest(cert.getEncoded());
    }
    
    private void verifyCA(X509Certificate cert) throws IOException {
    	// Cache
    	if (verified.contains(cert)) {
    		LOGGER.finer("Verification Cache Hit.");
    		return;
    	} else {
    		LOGGER.finer("Verification Cache Missed.");
    	}
    	
    	final String hashAlgorithm;
    	if (this.hashAlgorithm != null) {
    		hashAlgorithm = this.hashAlgorithm;
    	} else {
    		hashAlgorithm = "SHA-512";
    	}
    	final byte[] fingerprint;
    	try {
			fingerprint = createFingerprint(cert, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			// TODO
			throw new RuntimeException(e);
		} catch (CertificateEncodingException e) {
			// TODO
			throw new RuntimeException(e);
		}
		FingerprintVerificationCallback callback = new FingerprintVerificationCallback(fingerprint, hashAlgorithm);
		try {
			callbackHandler.handle(new Callback[] {callback});
		} catch (UnsupportedCallbackException e) {
			throw new RuntimeException(e);
		}
		if (callback.isVerified() == false) {
			throw new IOException("CA certificate fingerprint could not be verified (using " + hashAlgorithm + ").");
		} else {
			verified.add(cert);
		}
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
    	return selectCA(getCaCertificate());
    }
    
    private X509Certificate getRecipientCertificate() throws IOException {
    	final List<X509Certificate> certs = getCaCertificate();
    	// The CA or RA
    	return selectRecipient(certs);
    }
    
    private X509Certificate selectRecipient(List<X509Certificate> chain) {
    	int numCerts = chain.size();
    	if (numCerts == 2) {
    		final X509Certificate ca = selectCA(chain);
    		// The RA certificate is the other one.
    		int caIndex = chain.indexOf(ca);
    		int raIndex = 1 - caIndex;
    		
    		return chain.get(raIndex);
    	} else if (numCerts == 1) {
    		return chain.get(0);
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
        
        if (supportsDistributionPoints(ca)) {
        	// TODO
        	// http://tools.ietf.org/html/rfc5280#section-4.2.1.13
        	throw new UnsupportedOperationException();
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
    private boolean supportsDistributionPoints(X509Certificate ca) {
    	return ca.getExtensionValue("2.5.29.31") != null;
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
    public List<X509Certificate> enroll(char[] password) throws IOException, PKIOperationFailureException {
    	LOGGER.entering(getClass().getName(), "enroll", new Object[] {password});
    	
    	if (getCapabilities().isRenewalSupported() == false) {
    		
    	}
    	
    	final PKCSReq req = new PKCSReq(keyPair, identity, hashAlgorithm, password);
    	final CertStore store = createTransaction().performOperation(req, 20L);
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
			// TODO
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
     * This class is used for building immutable instances of the <code>Client</code>
     * class.  
     * <p>
     * Instances of this class can be configured by invoking the methods
     * declared below.  Following configuration, the {@see #build()} method should
     * be invoked to retrieve the new <code>Client</code> instance.
     * <p>
     * In order to create a valid <code>Client</code>, adopters must adhere to the
     * following pre-conditions.  The client must be able to...
     * <ul>
     *     <li>communicate with the SCEP server using:
     *         <ul>
     *             <li>{@see #url(URL)}
     *             <li>{@see #proxy(Proxy)} (if required)
     *         </ul>
     *     <li>identify itself using:
     *         <ul>
     *             <li>{@see #identity(X509Certificate, KeyPair)}
     *         </ul>
     *     <li>verify the CA certificate fingerprint using either:
     *         <ul>
     *             <li>{@see #callbackHandler(CallbackHandler)} OR
     *             <li>{@see #caFingerprint(byte[], String)}
     *         </ul>
     *     <li>select the correct CA profile, if supported, using:
     *         <ul>
     *             <li>{@see #caIdentifier(String)}
     *         </ul>
     * </ul>
     * <p>
     * If an instance of this class is not correctly configured according to the
     * above pre-conditions, the {@see #build()} method will throw an 
     * {@see IllegalStateException}.
     * <p>
     * Example Usage:
     * <pre>
     * URL url = new URL("http://www.example.org/scep/pkiclient.exe");
     * X509Certificate id = ...;
     * KeyPair pair = ...;
     * CallbackHandler handler = ...;
     * 
     * Client client = new Client.Builder().url(<b>url</b>).identity(<b>id</b>, <b>pair</b>).callbackHandler(<b>handler</b>).build();
     * </pre>
     * 
     * @author David Grant
     */
    public static class Builder {
    	private URL url;
    	private Proxy proxy = Proxy.NO_PROXY;
    	private byte[] fingerprint;
    	private String hashAlgorithm;
    	private String caIdentifier;
    	private X509Certificate identity;
    	private KeyPair keyPair;
    	private CallbackHandler callbackHandler;
    	
    	/**
    	 * Sets the {@see URL} of the SCEP server.
    	 * <p>
    	 * The URL should be of the following form:
    	 * <pre>
    	 * http(s?)://&lt;host&gt;[:&lt;port&gt;]/[&lt;path&gt;]pkiclient.exe
    	 * </pre>
    	 * 
    	 * @param url the URL.
    	 * @return the builder.
    	 */
    	public Builder url(URL url) {
    		this.url = url;
    		
    		return this;
    	}
    	
    	/**
    	 * Sets the {@see Proxy} needed to access the SCEP server, if any.
    	 * 
    	 * @param proxy the Proxy.
    	 * @return the builder.
    	 */
    	public Builder proxy(Proxy proxy) {
    		this.proxy = proxy;
    		
    		return this;
    	}
    	
    	/**
    	 * Sets the expected CA fingerprint.
    	 * <p>
    	 * If the fingerprint is not known, the {@see #callbackHandler(CallbackHandler)} 
    	 * method MUST be used instead. 
    	 * 
    	 * @param fingerprint the expected fingerprint.
    	 * @param hashAlgorithm the algorithm used to create the fingerprint.
    	 * @return the builder.
    	 */
    	public Builder caFingerprint(byte[] fingerprint, String hashAlgorithm) {
    		this.fingerprint = fingerprint;
    		this.hashAlgorithm = hashAlgorithm;
    		
    		return this;
    	}
    	
    	/**
    	 * Sets the CA identity string.
    	 * <p>
    	 * This property should be set if the CA supports multiple profiles.
    	 * 
    	 * @param caIdentifier the CA identity string.
    	 * @return the builder.
    	 */
    	public Builder caIdentifier(String caIdentifier) {
    		this.caIdentifier = caIdentifier;
    		
    		return this;
    	}
    	
    	/**
    	 * Sets the identity of the SCEP client.
    	 * <p>
    	 * The arguments provided to this method represent the identity of the
    	 * SCEP client, and not necessarily the entity to be enrolled. 
    	 * 
    	 * @param identity the client identity.
    	 * @param keyPair the RSA keypair of the client.
    	 * @return the builder.
    	 */
    	public Builder identity(X509Certificate identity, KeyPair keyPair) {
    		this.identity = identity;
    		this.keyPair = keyPair;
    		
    		return this;
    	}
    	
    	/**
    	 * Sets a {@link CallbackHandler} to use for handling the fingerprint
    	 * verification callback.
    	 * <p>
    	 * This method should be used if the CA fingerprint is not known at the 
    	 * time of client creation.  If a fingerprint is already known, the
    	 * {@see #caFingerprint(byte[], String)} method should be used instead.
    	 * <p>
    	 * The provided {@see CallbackHandler} MUST be able to handle the 
    	 * {@see FingerprintVerificationCallback} callback.
    	 * 
    	 * @param callbackHandler the callback handler.
    	 * @return the builder.
    	 */
    	public Builder callbackHandler(CallbackHandler callbackHandler) {
    		this.callbackHandler = callbackHandler;
    		
    		return this;
    	}
    	
    	/**
    	 * Constructs a new immutable instance of <code>Client</code>.
    	 * 
    	 * @return a new instance of <code>Client</code>
    	 * @throws IllegalStateException if any pre-conditions have been violated.
    	 */
    	public Client build() throws IllegalStateException {
    		return new Client(this);
    	}
    }
    
    /**
     * Basic CallbackHandler
     * 
     * @author David Grant
     */
    private static class FingerprintCallbackHandler implements CallbackHandler {
    	private final byte[] fingerprint;
    	private final String hashAlgorithm;
    	
    	public FingerprintCallbackHandler(byte[] fingerprint, String hashAlgorithm) {
    		this.fingerprint = fingerprint;
    		this.hashAlgorithm = hashAlgorithm;
    	}
    	
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof FingerprintVerificationCallback) {
					final FingerprintVerificationCallback callback = (FingerprintVerificationCallback) callbacks[i];
					
					if (callback.getAlgorithm().equals(hashAlgorithm) == false) {
						// We didn't supply this algorithm.
						callback.setVerified(false);
					} else if (Arrays.equals(callback.getFingerprint(), fingerprint) == false) {
						// The fingerprints don't match.
						callback.setVerified(false);
					} else {
						// OK!
						callback.setVerified(true);
					}
				} else {
					throw new UnsupportedCallbackException(callbacks[i]);
				}
			}
		}
    }
}
