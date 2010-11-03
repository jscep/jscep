/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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

package org.jscep.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.CertificateVerificationCallback;
import org.jscep.content.CaCapabilitiesContentHandler;
import org.jscep.content.CaCertificateContentHandler;
import org.jscep.content.NextCaCertificateContentHandler;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.GetCaCaps;
import org.jscep.request.GetCaCert;
import org.jscep.request.GetNextCaCert;
import org.jscep.response.Capabilities;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.Transport;
import org.jscep.util.LoggingUtil;

/**
 * This class represents a SCEP client, or Requester.
 */
public class Client {
	private static Logger LOGGER = LoggingUtil.getLogger(Client.class);
	private Map<String, Capabilities> capabilitiesCache = new HashMap<String, Capabilities>();
	private Set<X509Certificate> verified = new HashSet<X509Certificate>(1);
	private String preferredDigestAlg;
	private String preferredCipherAlg;
	
	// A requester MUST have the following information locally configured:
	//
    // 1.  The Certification Authority IP address or fully qualified domain name
    // 2.  The Certification Authority HTTP CGI script path
	//
	// We use a URL for this.
    private final URL url;
    // Before a requester can start a PKI transaction, it MUST have at least
    // one RSA key pair use for signing the SCEP pkiMessage (Section 3.1).
    //
    // The following identity and key pair is used for this case.
    private final X509Certificate identity;
    private final PrivateKey privKey;
    // A requester MUST have the following information locally configured:
    //
    // 3. The identifying information that is used for authentication of the 
    // Certification Authority in Section 4.1.1.  This information MAY be 
    // obtained from the user, or presented to the end user for manual 
    // authorization during the protocol exchange (e.g. the user indicates 
    // acceptance of a fingerprint via a user-interface element).
    //
    // We use a callback handler for this.
    private final CallbackHandler cbh;
    // The requester MUST have MESSAGE information configured if the
    // Certification Authority requires it (see Section 5.1).
    //
    // How does one determine that the CA _requires_ this?
    private final String profile;
    
    /**
     * Creates a new Client instance without a profile identifier.
     * <p>
     * This method will throw a NullPointerException if any of the arguments are null,
     * and an InvalidArgumentException if any of the arguments is invalid.
     * 
     * @param url the URL to the SCEP server.
     * @param identity the certificate to identify this client.
     * @param privKey the private key for the identity.
     * @param cbh the callback handler to check the CA identity.
     */
    public Client(URL url, X509Certificate identity, PrivateKey privKey, CallbackHandler cbh) {
    	this(url, identity, privKey, cbh, null);
    }
    
    /**
     * Creates a new Client instance with a profile identifier.
     * <p>
     * With the exception of the profile name, this method will throw a 
     * NullPointerException if any of the arguments are null, and an 
     * InvalidArgumentException if any of the arguments is invalid.
     * 
     * @param url the URL to the SCEP server.
     * @param identity the certificate to identify this client.
     * @param privKey the private key for the identity.
     * @param cbh the callback handler to check the CA identity.
     * @param profile the name of the CA profile.
     */
    public Client(URL url, X509Certificate identity, PrivateKey privKey, CallbackHandler cbh, String profile) {
    	this.url = url;
    	this.identity = identity;
    	this.privKey = privKey;
    	this.cbh = cbh;
    	this.profile = profile;
    	
    	validateInput();
    }
    
    /**
     * Returns the URL of the SCEP server used by this client.
     * 
     * @return the SCEP server URL.
     */
    @Deprecated
    public URL getURL() {
    	return url;
    }
    
    /**
     * Returns the profile name of the CA for this client.
     * <p>
     * If no profile is set, this method returns <code>null</code>.
     * 
     * @return the profile name.
     */
    @Deprecated
    public String getProfile() {
    	return profile;
    }
    
    /**
     * Returns the callback handler in use by this client.
     * 
     * @return the callback handler.
     */
    @Deprecated
    public CallbackHandler getCallbackHandler() {
    	return cbh;
    }
    
    /**
     * Returns the certificate in use by this client to identify itself.
     * 
     * @return the certificate.
     */
    @Deprecated
    public X509Certificate getIdentity() {
    	return identity;
    }
    
    /**
     * Returns the private key in use by this client.
     * 
     * @return the private key.
     */
    @Deprecated
    public PrivateKey getPrivateKey() {
    	return privKey;
    }
    
    /**
     * Validates all the input to this client.
     * 
     * @throws NullPointerException if any member variables are null.
     * @throws IllegalArgumentException if any member variables are invalid.
     */
    private void validateInput() throws NullPointerException, IllegalArgumentException {
    	// Check for null values first.
    	if (url == null) {
    		throw new NullPointerException("URL should not be null");
    	}
    	if (identity == null) {
    		throw new NullPointerException("Identity should not be null");
    	}
    	if (privKey == null) {
    		throw new NullPointerException("Private key should not be null");
    	}
    	if (cbh == null) {
    		throw new NullPointerException("Callback handler should not be null");
    	}
    	
    	if (identity.getPublicKey().getAlgorithm().equals("RSA") == false) {
    		throw new IllegalArgumentException("Public key algorithm should be RSA");
    	}
    	if (privKey.getAlgorithm().equals("RSA") == false) {
    		throw new IllegalArgumentException("Private key algorithm should be RSA");
    	}
    	if (url.getProtocol().matches("^https?$") == false) {
    		throw new IllegalArgumentException("URL protocol should be HTTP or HTTPS");
    	}
    	if (url.getPath().endsWith("pkiclient.exe") == false) {
    		throw new IllegalArgumentException("URL should end with pkiclient.exe");
    	}
    	if (url.getRef() != null) {
    		throw new IllegalArgumentException("URL should contain no reference");
    	}
    	if (url.getQuery() != null) {
    		throw new IllegalArgumentException("URL should contain no query string");
    	}
    }
    
    private PkiMessageEncoder getEncoder() throws IOException {
    	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(getRecipientCertificate());
    	
		return new PkiMessageEncoder(privKey, identity, envEncoder);
    }
    
    private PkiMessageDecoder getDecoder() {
    	PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(privKey);
    	
		return new PkiMessageDecoder(envDecoder);
    }
    
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.2.4
     */
    private boolean supportsDistributionPoints(X509Certificate issuerCertificate) {
    	return issuerCertificate.getExtensionValue("2.5.29.31") != null;
    }
    
    /**
     * Returns any certificate revocation lists relating to the current CA.
     *  
     * @return a collection of CRLs
     * @throws IOException if any I/O error occurs.
     * @throws PkiOperationFailureException if the operation fails.
     */
    public Collection<? extends CRL> getCrl() throws IOException, OperationFailureException {
    	// TRANSACTIONAL
    	// CRL query
    	final X509Certificate ca = retrieveCA();
    	if (supportsDistributionPoints(ca)) {
    		throw new RuntimeException("Unimplemented");
    	}
    	
    	X509Name name = new X509Name(ca.getIssuerX500Principal().toString());
    	BigInteger serialNumber = ca.getSerialNumber();
    	IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serialNumber);
    	final Transaction t = new NonEnrollmentTransaction(getEncoder(), getDecoder(), iasn, MessageType.GetCRL);
    	t.send(createTransport());
    	
    	if (t.getState() == State.CERT_ISSUED) {
			try {
				return t.getCertStore().getCRLs(null);
			} catch (CertStoreException e) {
				throw new RuntimeException(e);
			}
		} else if (t.getState() == State.CERT_REQ_PENDING) {
			throw new IllegalStateException();
		} else {
			throw new OperationFailureException(t.getFailInfo());
		}
    }

    /**
     * Returns the certificate corresponding to the provided serial number, as issued
     * by the current CA.
     * 
     * @param serial the serial number.
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws PkiOperationFailureException if the operation fails.
     */
    public Collection<? extends Certificate> getCertificate(BigInteger serial) throws IOException, OperationFailureException {
    	// TRANSACTIONAL
    	// Certificate query
    	final X509Certificate ca = retrieveCA();;
    	
    	X509Name name = new X509Name(ca.getIssuerX500Principal().toString());
    	BigInteger serialNumber = ca.getSerialNumber();
    	IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serialNumber);
    	final Transaction t = new NonEnrollmentTransaction(getEncoder(), getDecoder(), iasn, MessageType.GetCert);
		t.send(createTransport());
    	
		if (t.getState() == State.CERT_ISSUED) {
			try {
				return t.getCertStore().getCertificates(null);
			} catch (CertStoreException e) {
				throw new RuntimeException(e);
			}
		} else if (t.getState() == State.CERT_REQ_PENDING) {
			throw new IllegalStateException();
		} else {
			throw new OperationFailureException(t.getFailInfo());
		}
    }
    
    /**
     * Enrolls the provided CSR into a PKI.
     * 
     * @param csr the certificate signing request
     * @return the enrollment transaction.
     * @throws IOException if any I/O error occurs.
     */
    public EnrollmentTransaction enrollCertificate(CertificationRequest csr) throws IOException {
    	// TRANSACTIONAL
    	// Certificate enrollment
    	final EnrollmentTransaction t = new EnrollmentTransaction(getEncoder(), getDecoder(), csr);
    	t.send(createTransport());
    	
    	return t;
    }
    
    /**
     * Creates a new transport based on the capabilities of the server.
     * 
     * @return the new transport.
     * @throws IOException if any I/O error occurs.
     */
    private Transport createTransport() throws IOException {
    	LOGGER.entering(getClass().getName(), "createTransport");
    	
    	final Transport t;
    	if (getCaCapabilities(true).isPostSupported()) {
    		t = Transport.createTransport(Transport.Method.POST, url);
    	} else {
    		t = Transport.createTransport(Transport.Method.GET, url);
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
    public Capabilities getCaCapabilities() throws IOException {
    	// NON-TRANSACTIONAL
    	return getCaCapabilities(false);
    }
    
    private Capabilities getCaCapabilities(boolean useCache) throws IOException {
    	// NON-TRANSACTIONAL
    	LOGGER.entering(getClass().getName(), "getCaCapabilities", useCache);
    	
    	Capabilities caps = null;
    	if (useCache == true) {
    		caps = capabilitiesCache.get(profile);
    	}
    	if (caps == null) {
	    	final GetCaCaps req = new GetCaCaps(profile, new CaCapabilitiesContentHandler());
	        final Transport trans = Transport.createTransport(Transport.Method.GET, url);
	        caps = trans.sendRequest(req);
	        capabilitiesCache.put(profile, caps);
    	}
        
        LOGGER.exiting(getClass().getName(), "getCaCapabilities", caps);
        return caps;
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
    	// NON-TRANSACTIONAL
    	// CA and RA public key distribution
    	LOGGER.entering(getClass().getName(), "getCaCertificate");
    	final GetCaCert req = new GetCaCert(profile, new CaCertificateContentHandler());
        final Transport trans = Transport.createTransport(Transport.Method.GET, url);
        
        final List<X509Certificate> certs = trans.sendRequest(req);
        verifyCA(selectCA(certs));
        
        LOGGER.exiting(getClass().getName(), "getCaCertificate", certs);
        return certs;
    }
    
    private void verifyCA(X509Certificate cert) throws IOException {
    	// Cache
    	if (verified.contains(cert)) {
    		LOGGER.finer("Verification Cache Hit.");
    		return;
    	} else {
    		LOGGER.finer("Verification Cache Missed.");
    	}

		CertificateVerificationCallback callback = new CertificateVerificationCallback(cert);
		try {
			cbh.handle(new Callback[] {callback});
		} catch (UnsupportedCallbackException e) {
			throw new RuntimeException(e);
		}
		if (callback.isVerified() == false) {
			throw new IOException("CA certificate fingerprint could not be verified.");
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
    public List<X509Certificate> getRolloverCertificate() throws IOException {
    	// NON-TRANSACTIONAL
    	if (getCaCapabilities().isRolloverSupported() == false) {
    		throw new UnsupportedOperationException();
    	}
    	final X509Certificate issuer = retrieveCA();
    	
    	final Transport trans = Transport.createTransport(Transport.Method.GET, url);
    	final GetNextCaCert req = new GetNextCaCert(profile, new NextCaCertificateContentHandler(issuer));
    	
    	return trans.sendRequest(req);
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
    
    void setPreferredCipherAlgorithm(String algorithm) {
    	preferredCipherAlg = algorithm;
    }
    
    void setPreferredDigestAlgorithm(String algorithm) {
    	preferredDigestAlg = algorithm;
    }
}
