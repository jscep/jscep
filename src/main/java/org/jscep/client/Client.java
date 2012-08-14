/*
 * Copyright (c) 2009-2012 David Grant
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
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.HttpGetTransport;
import org.jscep.transport.HttpPostTransport;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.jscep.transport.response.GetCaCertResponseHandler;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <tt>Client</tt> class is used for interacting with a SCEP server.
 * <p>
 * Typical usage might look like so:
 * 
 * <pre>
 * // Create the client
 * URL server = new URL(&quot;http://jscep.org/scep/pkiclient.exe&quot;);
 * CertificateVerifier verifier = new ConsoleCertificateVerifier();
 * Client client = new Client(server, verifier);
 * 
 * // Invoke operations on the client.
 * client.getCaCapabilities();
 * </pre>
 * 
 * Each of the operations of this class is overloaded with a profile argument to
 * support SCEP servers with multiple (or mandatory) profile names.
 */
public final class Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);

    // A requester MUST have the following information locally configured:
    //
    // 1. The Certification Authority IP address or fully qualified domain name
    // 2. The Certification Authority HTTP CGI script path
    //
    // We use a URL for this.
    private final URL url;
    // A requester MUST have the following information locally configured:
    //
    // 3. The identifying information that is used for authentication of the
    // Certification Authority in Section 4.1.1. This information MAY be
    // obtained from the user, or presented to the end user for manual
    // authorization during the protocol exchange (e.g. the user indicates
    // acceptance of a fingerprint via a user-interface element).
    //
    // We use a callback handler for this.
    private final CallbackHandler handler;

    /**
     * Constructs a new <tt>Client</tt> instance using the provided
     * <tt>CallbackHandler</tt> for the provided URL.
     * <p>
     * The <tt>CallbackHandler</tt> must be able to handle
     * {@link CertificateVerificationCallback}. Unless the
     * <tt>CallbackHandler</tt> will be used to handle additional
     * <tt>Callback</tt>s, users of this class are recommended to use the
     * {@link #Client(URL, CertificateVerifier)} constructor instead.
     * 
     * @param url
     *            the URL of the SCEP server.
     * @param handler
     *            the callback handler used to check the CA identity.
     */
    public Client(URL url, CallbackHandler handler) {
	this.url = url;
	this.handler = handler;

	validateInput();
    }

    /**
     * Constructs a new <tt>Client</tt> instance using the provided
     * <tt>CertificateVerifier</tt> for the provided URL.
     * <p/>
     * The provided <tt>CertificateVerifier</tt> is used to verify that the
     * identity of the SCEP server matches what the client expects.
     * 
     * @param url
     *            the URL of the SCEP server.
     * @param verifier
     *            the verifier used to check the CA identity.
     */
    public Client(URL url, CertificateVerifier verifier) {
	this.url = url;
	this.handler = new DefaultCallbackHandler(verifier);

	validateInput();
    }

    /**
     * Validates all the input to this client.
     * 
     * @throws NullPointerException
     *             if any member variables are null.
     * @throws IllegalArgumentException
     *             if any member variables are invalid.
     */
    private void validateInput() throws NullPointerException,
	    IllegalArgumentException {
	// Check for null values first.
	if (url == null) {
	    throw new NullPointerException("URL should not be null");
	}
	if (!url.getProtocol().matches("^https?$")) {
	    throw new IllegalArgumentException(
		    "URL protocol should be HTTP or HTTPS");
	}
	if (url.getRef() != null) {
	    throw new IllegalArgumentException(
		    "URL should contain no reference");
	}
	if (url.getQuery() != null) {
	    throw new IllegalArgumentException(
		    "URL should contain no query string");
	}
	if (handler == null) {
	    throw new NullPointerException(
		    "Callback handler should not be null");
	}
    }

    // INFORMATIONAL REQUESTS

    /**
     * Retrieves the set of SCEP capabilities from the CA.
     * 
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities() {
	// NON-TRANSACTIONAL
	return getCaCapabilities(null);
    }

    /**
     * Retrieves the capabilities of the SCEP server.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     * 
     * @param profile
     *            the SCEP server profile.
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities(final String profile) {
	LOGGER.debug("Determining capabilities of SCEP server");
	// NON-TRANSACTIONAL
	final GetCaCapsRequest req = new GetCaCapsRequest(profile);
	final Transport trans = new HttpGetTransport(url);
	try {
	    return trans.sendRequest(req, new GetCaCapsResponseHandler());
	} catch (TransportException e) {
	    LOGGER.warn("Transport problem when determining capabilities.  Using empty capabilities.");
	    return new Capabilities();
	}
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     * 
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getCaCertificate() throws ClientException {
	return getCaCertificate(null);
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     * 
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getCaCertificate(final String profile)
	    throws ClientException {
	LOGGER.debug("Retriving current CA certificate");
	// NON-TRANSACTIONAL
	// CA and RA public key distribution
	final GetCaCertRequest req = new GetCaCertRequest(profile);
	final Transport trans = new HttpGetTransport(url);

	CertStore store;
	try {
	    store = trans.sendRequest(req, new GetCaCertResponseHandler());
	} catch (TransportException e) {
	    throw new ClientException(e);
	}
	verifyCA(selectIssuerCertificate(store));

	return store;
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     * 
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate() throws ClientException {
	return getRolloverCertificate(null);
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     * 
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate(final String profile)
	    throws ClientException {
	LOGGER.debug("Retriving next CA certificate from CA");
	// NON-TRANSACTIONAL
	if (!getCaCapabilities(profile).isRolloverSupported()) {
	    throw new UnsupportedOperationException();
	}
	final X509Certificate signer = getSignerCertificate(profile);

	final Transport trans = new HttpGetTransport(url);
	final GetNextCaCertRequest req = new GetNextCaCertRequest(profile);

	try {
	    return trans.sendRequest(req, new GetNextCaCertResponseHandler(
		    signer));
	} catch (TransportException e) {
	    throw new ClientException(e);
	}
    }

    // TRANSACTIONAL

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    public X509CRL getRevocationList(X509Certificate identity, PrivateKey key,
	    final X500Principal issuer, final BigInteger serial)
	    throws ClientException, OperationFailureException {
	return getRevocationList(identity, key, issuer, serial, null);
    }

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @param profile
     *            the SCEP server profile.
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    @SuppressWarnings("unchecked")
    public X509CRL getRevocationList(X509Certificate identity, PrivateKey key,
	    final X500Principal issuer, final BigInteger serial,
	    final String profile) throws ClientException,
	    OperationFailureException {
	LOGGER.debug("Retriving CRL from CA");
	// TRANSACTIONAL
	// CRL query
	final CertStore store = getCaCertificate(profile);
	final X509Certificate ca = selectIssuerCertificate(store);
	final X509Certificate signer = selectSignerCertificate(store);
	if (supportsDistributionPoints(ca)) {
	    throw new RuntimeException("Unimplemented");
	}

	X500Name name = new X500Name(issuer.getName());
	IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
	Transport transport = createTransport(profile);
	final Transaction t = new NonEnrollmentTransaction(transport,
		getEncoder(identity, key, profile), getDecoder(identity, key,
			signer), iasn, MessageType.GET_CRL);
	State state;
	try {
	    state = t.send();
	} catch (TransactionException e) {
	    throw new ClientException(e);
	}

	if (state == State.CERT_ISSUED) {
	    try {
		Collection<X509CRL> crls = (Collection<X509CRL>) t
			.getCertStore().getCRLs(null);
		if (crls.size() == 0) {
		    return null;
		}
		return crls.iterator().next();
	    } catch (CertStoreException e) {
		throw new RuntimeException(e);
	    }
	} else if (state == State.CERT_REQ_PENDING) {
	    throw new IllegalStateException();
	} else {
	    throw new OperationFailureException(t.getFailInfo());
	}
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(X509Certificate identity, PrivateKey key,
	    BigInteger serial) throws ClientException,
	    OperationFailureException {
	return getCertificate(identity, key, serial, null);
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(X509Certificate identity, PrivateKey key,
	    BigInteger serial, String profile)
	    throws OperationFailureException, ClientException {
	LOGGER.debug("Retriving certificate from CA");
	// TRANSACTIONAL
	// Certificate query
	final CertStore store = getCaCertificate(profile);
	final X509Certificate ca = selectIssuerCertificate(store);
	final X509Certificate signer = selectSignerCertificate(store);

	X500Name name = new X500Name(ca.getIssuerX500Principal().toString());
	IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
	Transport transport = createTransport(profile);
	final Transaction t = new NonEnrollmentTransaction(transport,
		getEncoder(identity, key, profile), getDecoder(identity, key,
			signer), iasn, MessageType.GET_CERT);

	State state;
	try {
	    state = t.send();
	} catch (TransactionException e) {
	    throw new ClientException(e);
	}

	if (state == State.CERT_ISSUED) {
	    return t.getCertStore();
	} else if (state == State.CERT_REQ_PENDING) {
	    throw new IllegalStateException();
	} else {
	    throw new OperationFailureException(t.getFailInfo());
	}
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provider <tt>CertificationRequest</tt> into the
     * PKI represented by the SCEP server.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the operation fails.
     * @throws PollingTerminatedException
     *             if polling is terminated
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(X509Certificate identity, PrivateKey key,
	    final PKCS10CertificationRequest csr) throws ClientException,
	    TransactionException {
	return enrol(identity, key, csr, null);
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provider <tt>CertificationRequest</tt> into the
     * PKI represented by the SCEP server.
     * 
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the operation fails.
     * @throws PollingTerminatedException
     *             if polling is terminated
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(X509Certificate identity, PrivateKey key,
	    final PKCS10CertificationRequest csr, String profile)
	    throws ClientException, TransactionException {
	LOGGER.debug("Enrolling certificate with CA");
	// TRANSACTIONAL
	// Certificate enrollment
	final Transport transport = createTransport(profile);
	CertStore store = getCaCertificate(profile);
	X509Certificate rcpt = selectRecipientCertificate(store);
	X509Certificate signer = selectSignerCertificate(store);
	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(rcpt);
	PkiMessageEncoder encoder = new PkiMessageEncoder(key, identity,
		envEncoder);
	PkiMessageDecoder decoder = getDecoder(identity, key, signer);
	final EnrollmentTransaction trans = new EnrollmentTransaction(
		transport, encoder, decoder, csr);
	return send(trans);
    }

    public EnrollmentResponse poll(X509Certificate identity,
	    PrivateKey identityKey, X500Principal subject, TransactionId transId)
	    throws ClientException, TransactionException {
	return poll(identity, identityKey, subject, transId, null);
    }

    public EnrollmentResponse poll(X509Certificate identity,
	    PrivateKey identityKey, X500Principal subject,
	    TransactionId transId, String profile) throws ClientException,
	    TransactionException {
	final Transport transport = createTransport(profile);
	CertStore store = getCaCertificate(profile);
	X509Certificate rcpt = selectRecipientCertificate(store);
	X509Certificate issuer = selectIssuerCertificate(store);
	X509Certificate signer = selectSignerCertificate(store);
	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(rcpt);
	PkiMessageEncoder encoder = new PkiMessageEncoder(identityKey,
		identity, envEncoder);
	PkiMessageDecoder decoder = getDecoder(identity, identityKey, signer);
	IssuerAndSubject ias = new IssuerAndSubject(X509Util.toX509Name(issuer
		.getIssuerX500Principal()), X509Util.toX509Name(subject));

	final EnrollmentTransaction trans = new EnrollmentTransaction(
		transport, encoder, decoder, ias, transId);
	return send(trans);
    }

    private EnrollmentResponse send(final EnrollmentTransaction trans)
	    throws TransactionException {
	State s = trans.send();

	if (s == State.CERT_ISSUED) {
	    return new EnrollmentResponse(trans.getId(), trans.getCertStore());
	} else if (s == State.CERT_REQ_PENDING) {
	    return new EnrollmentResponse(trans.getId());
	} else {
	    return new EnrollmentResponse(trans.getId(), trans.getFailInfo());
	}
    }

    private PkiMessageEncoder getEncoder(X509Certificate identity,
	    PrivateKey priKey, String profile) throws ClientException {
	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
		getRecipientCertificate(profile));

	return new PkiMessageEncoder(priKey, identity, envEncoder);
    }

    private PkiMessageDecoder getDecoder(X509Certificate identity,
	    PrivateKey key, X509Certificate signer) {
	PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
		identity, key);

	return new PkiMessageDecoder(envDecoder, signer);
    }

    /**
     * @param issuerCertificate
     *            certificate to test
     * @return true if the certificate supports distribution points, false
     *         otherwise
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.2.4
     */
    private boolean supportsDistributionPoints(X509Certificate issuerCertificate) {
	return issuerCertificate
		.getExtensionValue(X509Extension.cRLDistributionPoints.getId()) != null;
    }

    /**
     * Creates a new transport based on the capabilities of the server.
     * 
     * @param profile
     *            profile to use for determining if HTTP POST is supported
     * @return the new transport.
     * @throws IOException
     *             if any I/O error occurs.
     */
    private Transport createTransport(final String profile) {
	final Transport t;
	if (getCaCapabilities(profile).isPostSupported()) {
	    t = new HttpPostTransport(url);
	} else {
	    t = new HttpGetTransport(url);
	}

	return t;
    }

    private void verifyCA(X509Certificate cert) throws ClientException {
	CertificateVerificationCallback callback = new CertificateVerificationCallback(
		cert);
	try {
	    LOGGER.debug("Requesting certificate verification.");
	    Callback[] callbacks = new Callback[1];
	    callbacks[0] = callback;
	    handler.handle(callbacks);
	} catch (UnsupportedCallbackException e) {
	    LOGGER.debug("Certificate verification failed.");
	    throw new ClientException(e);
	} catch (IOException e) {
	    throw new ClientException(e);
	}
	if (!callback.isVerified()) {
	    LOGGER.debug("Certificate verification failed.");
	    throw new ClientException(
		    "CA certificate fingerprint could not be verified.");
	} else {
	    LOGGER.debug("Certificate verification passed.");
	}
    }

    private X509Certificate getRecipientCertificate(String profile)
	    throws ClientException {
	final CertStore store = getCaCertificate(profile);
	// The CA or RA
	return selectRecipientCertificate(store);
    }

    private X509Certificate getSignerCertificate(String profile)
	    throws ClientException {
	final CertStore store = getCaCertificate(profile);
	// The CA or RA
	return selectSignerCertificate(store);
    }

    private X509Certificate selectRecipientCertificate(CertStore store) {
	CertStoreInspector certPair = CertStoreInspector.inspect(store);

	return certPair.getRecipient();
    }

    private X509Certificate selectSignerCertificate(CertStore store) {
	CertStoreInspector certPair = CertStoreInspector.inspect(store);

	return certPair.getSigner();
    }

    private X509Certificate selectIssuerCertificate(CertStore store) {
	CertStoreInspector certPair = CertStoreInspector.inspect(store);

	return certPair.getIssuer();
    }
}
