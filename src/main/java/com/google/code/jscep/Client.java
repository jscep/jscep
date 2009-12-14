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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.google.code.jscep.operations.GetCRL;
import com.google.code.jscep.operations.GetCert;
import com.google.code.jscep.operations.PkiMessage;
import com.google.code.jscep.request.GetCACaps;
import com.google.code.jscep.request.GetCACert;
import com.google.code.jscep.request.GetNextCACert;
import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.transaction.Transaction;
import com.google.code.jscep.transaction.TransactionFactory;
import com.google.code.jscep.transport.Transport;

/**
 * SCEP Client
 */
public class Client {
	private final static Logger LOGGER = Logger.getLogger(Client.class.getName());
    private URL url;						// Required
    private byte[] caDigest;				// Required
    private String digestAlgorithm;			// Optional
    private Proxy proxy;					// Optional
    private String caIdentifier;			// Optional
    private KeyPair keyPair;				// Optional
    private X509Certificate identity;		// Optional
    
    public Client(ClientConfiguration config) throws IllegalStateException, NoSuchAlgorithmException, CertificateEncodingException, IOException, ScepException {
    	url = config.getUrl();
    	proxy = config.getProxy();
    	caDigest = config.getCaDigest();
    	caIdentifier = config.getCaIdentifier();
    	keyPair = config.getKeyPair();
    	identity = config.getIdentity();
    	digestAlgorithm = config.getDigestAlgorithm();

    	X500Principal subject = config.getSubject();
    	X509Certificate ca = config.getCaCertificate();
    	
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
		List<String> algorithms = new LinkedList<String>();
		algorithms.add("MD5");
		algorithms.add("SHA-1");
		algorithms.add("SHA-256");
		algorithms.add("SHA-512");
		if (algorithms.contains(digestAlgorithm) == false) {
			throw new IllegalStateException(digestAlgorithm + " is not a valid digest algorithm");
		}
		
		if (ca != null) {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			caDigest = digest.digest(ca.getTBSCertificate());
		} else {
			ca = retrieveCA();
		}
		
		// Check renewal
		if (subject == null) {
			if (isSelfSigned(identity) == false) {
				if (identity.getIssuerX500Principal().equals(ca.getSubjectX500Principal())) {
					LOGGER.fine("Certificate is signed by CA, so this is a renewal.");
				} else {
					LOGGER.fine("Certificate is signed by another CA, bit this is still a renewal.");
				}
				try {
					LOGGER.fine("Checking if the CA supports certificate renewal...");
					if (getCapabilities().supportsRenewal() == false) {
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
    
    private boolean isSelfSigned(X509Certificate cert) {
    	return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
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
    
    private Transaction createTransaction() throws IOException, CertificateEncodingException, NoSuchAlgorithmException, ScepException {
    	return TransactionFactory.createTransaction(createTransport(), retrieveSigningCertificate(), identity, keyPair, getCapabilities().getPreferredMessageDigest());
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
    	GetCACaps req = new GetCACaps(caIdentifier);
        Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);

        return trans.sendMessage(req);
    }

    private List<X509Certificate> getCaCertificate() throws IOException {
    	GetCACert req = new GetCACert(caIdentifier);
        Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
        
        return trans.sendMessage(req);
    }
    
    public List<X509Certificate> getNextCA() throws IOException, CertificateEncodingException, NoSuchAlgorithmException, ScepException {
    	X509Certificate ca = retrieveCA();
    	
    	Transport trans = Transport.createTransport(Transport.Method.GET, url, proxy);
    	GetNextCACert req = new GetNextCACert(ca, caIdentifier);
    	
    	return trans.sendMessage(req);
    }
    
    private X509Certificate retrieveCA() throws IOException, NoSuchAlgorithmException, CertificateEncodingException, ScepException {
    	final List<X509Certificate> certs = getCaCertificate();
    	
    	// Validate
    	final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
    	System.out.println(Arrays.toString(md.digest(certs.get(0).getEncoded())));
        if (Arrays.equals(caDigest, md.digest(certs.get(0).getEncoded())) == false) {
        	throw new ScepException("CA Fingerprint Error");
        }
    	
    	return certs.get(0);
    }
    
    private X509Certificate retrieveSigningCertificate() throws IOException, NoSuchAlgorithmException, CertificateEncodingException, ScepException {
    	List<X509Certificate> certs = getCaCertificate();
    	
    	// Validate
    	MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        if (Arrays.equals(caDigest, md.digest(certs.get(0).getEncoded())) == false) {
        	throw new ScepException("CA Fingerprint Error");
        }
    	
    	if (certs.size() > 1) {
    		// RA
    		return certs.get(1);
    	} else {
    		// CA
    		return certs.get(0);
    	}
    }
    
    /**
     * Retrieves the certificate revocation list for the current CA.
     * 
     * @return the certificate revocation list.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException if any SCEP error occurs.
     * @throws GeneralSecurityException if any security error occurs.
     */
    public List<X509CRL> getCrl() throws IOException, ScepException, GeneralSecurityException {
        X509Certificate ca = retrieveCA();
        
        if (supportsDistributionPoints()) {
        	return null;
        } else {
	        // PKI Operation
	        PkiMessage req = new GetCRL(ca.getIssuerX500Principal(), ca.getSerialNumber());
	        CertStore store;
			try {
				store = createTransaction().performOperation(req);
			} catch (RequestPendingException e) {
				throw new RuntimeException(e);
			} catch (EnrollmentFailureException e) {
				throw new RuntimeException(e);
			}
	        
	        return getCRLs(store.getCRLs(null));
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
     * 
     * @param password the enrollment password.
     * @return the enrolled certificate.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException
     * @throws GeneralSecurityException
     * @throws UnsupportedCallbackException 
     */
    public EnrollmentResult enroll(char[] password) throws Exception {
        final X509Certificate signer = retrieveSigningCertificate();
        
        return new InitialEnrollmentTask(createTransport(), signer, keyPair, identity, password, getCapabilities().getPreferredMessageDigest()).call();
    }

    /**
     * Retrieves the certificate corresponding to the given serial number.
     * 
     * @param serial the serial number of the certificate.
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws ScepException
     * @throws GeneralSecurityException
     * @throws EnrollmentFailureException 
     * @throws RequestPendingException 
     * @throws UnsupportedCallbackException 
     * @throws RequestPendingException 
     * @throws EnrollmentFailureException 
     */
    public X509Certificate getCert(BigInteger serial) throws IOException, ScepException, GeneralSecurityException {
    	final X509Certificate ca = retrieveCA();
        // PKI Operation
        PkiMessage req = new GetCert(ca.getIssuerX500Principal(), serial);
        CertStore store;
		try {
			store = createTransaction().performOperation(req);
		} catch (RequestPendingException e) {
			throw new RuntimeException(e);
		} catch (EnrollmentFailureException e) {
			throw new RuntimeException(e);
		}

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
