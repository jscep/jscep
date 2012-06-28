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
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.CertificateVerificationCallback;
import org.jscep.content.CaCapabilitiesContentHandler;
import org.jscep.content.CaCertificateContentHandler;
import org.jscep.content.InvalidContentException;
import org.jscep.content.InvalidContentTypeException;
import org.jscep.content.NextCaCertificateContentHandler;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.request.GetCaCaps;
import org.jscep.request.GetCaCert;
import org.jscep.request.GetNextCaCert;
import org.jscep.response.Capabilities;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents a SCEP client, or Requester.
 */
public final class Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);
    private Map<String, Capabilities> capabilitiesCache = new HashMap<String, Capabilities>();
    private Set<X509Certificate> verified = new HashSet<X509Certificate>(1);

    // A requester MUST have the following information locally configured:
    //
    // 1. The Certification Authority IP address or fully qualified domain name
    // 2. The Certification Authority HTTP CGI script path
    //
    // We use a URL for this.
    private final URL url;
    // Before a requester can start a PKI transaction, it MUST have at least
    // one RSA key pair use for signing the SCEP pkiMessage (Section 3.1).
    //
    // The following identity and key pair is used for this case.
    private final X509Certificate identity;
    private final PrivateKey priKey;
    // A requester MUST have the following information locally configured:
    //
    // 3. The identifying information that is used for authentication of the
    // Certification Authority in Section 4.1.1. This information MAY be
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
     * <p/>
     * This method will throw a NullPointerException if any of the arguments are
     * null, and an InvalidArgumentException if any of the arguments is invalid.
     * 
     * @param url the URL to the SCEP server.
     * @param client the certificate to identify this client.
     * @param priKey the private key for the identity.
     * @param cbh the callback handler to check the CA identity.
     */
    public Client(URL url, X509Certificate client, PrivateKey priKey,
            CallbackHandler cbh) {
        this(url, client, priKey, cbh, null);
    }

    /**
     * Creates a new Client instance with a profile identifier.
     * <p/>
     * With the exception of the profile name, this method will throw a
     * NullPointerException if any of the arguments are null, and an
     * InvalidArgumentException if any of the arguments is invalid.
     * 
     * @param url the URL to the SCEP server.
     * @param client the certificate to identify this client.
     * @param priKey the private key for the identity.
     * @param cbh the callback handler to check the CA identity.
     * @param profile the name of the CA profile.
     */
    public Client(URL url, X509Certificate client, PrivateKey priKey,
            CallbackHandler cbh, String profile) {
        this.url = url;
        this.identity = client;
        this.priKey = priKey;
        this.cbh = cbh;
        this.profile = profile;

        validateInput();
    }

    // INFORMATIONAL REQUESTS

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

    /**
     * Retrieves the CA certificate.
     * <p/>
     * If the CA is using an RA, the RA certificate will also be present in the
     * returned list.
     * 
     * @return the list of certificates.
     * @throws IOException if any I/O error occurs.
     */
    public CertStore getCaCertificate() throws IOException {
        LOGGER.debug("Retriving current CA certificate");
        // NON-TRANSACTIONAL
        // CA and RA public key distribution
        final GetCaCert req = new GetCaCert(profile);
        final Transport trans = Transport.createTransport(Transport.Method.GET,
                url);

        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw ioe(e);
        }
        CertStore store;
        try {
            store = trans.sendRequest(req, new CaCertificateContentHandler(
                    factory));
        } catch (TransportException e) {
            throw ioe(e);
        } catch (InvalidContentTypeException e) {
            throw ioe(e);
        } catch (InvalidContentException e) {
            throw ioe(e);
        }
        verifyCA(selectIssuerCertificate(store));

        return store;
    }

    private IOException ioe(Throwable t) {
        IOException e = new IOException();
        e.initCause(t);

        return e;
    }

    /**
     * Retrieves the "rollover" certificate to be used by the CA.
     * <p/>
     * If the CA is using an RA, the RA certificate will be present in the
     * returned list.
     * 
     * @return the list of certificates.
     * @throws IOException if any I/O error occurs.
     */
    public List<X509Certificate> getRolloverCertificate() throws IOException {
        LOGGER.debug("Retriving next CA certificate from CA");
        // NON-TRANSACTIONAL
        if (!getCaCapabilities().isRolloverSupported()) {
            throw new UnsupportedOperationException();
        }
        final X509Certificate issuer = getRecipientCertificate();

        final Transport trans = Transport.createTransport(Transport.Method.GET,
                url);
        final GetNextCaCert req = new GetNextCaCert(profile);

        try {
            return trans.sendRequest(req, new NextCaCertificateContentHandler(
                    issuer));
        } catch (TransportException e) {
            throw ioe(e);
        } catch (InvalidContentTypeException e) {
            throw ioe(e);
        } catch (InvalidContentException e) {
            throw ioe(e);
        }
    }

    // TRANSACTIONAL

    /**
     * Returns the current CA's certificate revocation list
     * 
     * @param issuer the issuer X500 name
     * @param serial the serial number of the certificate
     * @return a collection of CRLs
     * @throws IOException if any I/O error occurs.
     * @throws OperationFailureException if the operation fails.
     */
    @SuppressWarnings("unchecked")
    public X509CRL getRevocationList(X500Principal issuer, BigInteger serial)
            throws IOException, OperationFailureException {
        LOGGER.debug("Retriving CRL from CA");
        // TRANSACTIONAL
        // CRL query
        final X509Certificate ca = retrieveCA();
        if (supportsDistributionPoints(ca)) {
            throw new RuntimeException("Unimplemented");
        }

        X500Name name = new X500Name(issuer.getName());
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        Transport transport = createTransport();
        final Transaction t = new NonEnrollmentTransaction(transport,
                getEncoder(), getDecoder(), iasn, MessageType.GET_CRL);
        State state;
        try {
            state = t.send();
        } catch (TransportException e) {
            throw ioe(e);
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
     * Returns the certificate corresponding to the provided serial number, as
     * issued by the current CA.
     * 
     * @param serial the serial number.
     * @return the certificate.
     * @throws IOException if any I/O error occurs.
     * @throws OperationFailureException if the operation fails.
     */
    @SuppressWarnings("unchecked")
    public List<X509Certificate> getCertificate(BigInteger serial)
            throws IOException, OperationFailureException {
        LOGGER.debug("Retriving certificate from CA");
        // TRANSACTIONAL
        // Certificate query
        final X509Certificate ca = retrieveCA();

        X500Name name = new X500Name(ca.getIssuerX500Principal().toString());
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        Transport transport = createTransport();
        final Transaction t = new NonEnrollmentTransaction(transport,
                getEncoder(), getDecoder(), iasn, MessageType.GET_CERT);

        State state;
        try {
            state = t.send();
        } catch (TransportException e) {
            throw ioe(e);
        }

        if (state == State.CERT_ISSUED) {
            try {
                Collection<X509Certificate> certs = (Collection<X509Certificate>) t
                        .getCertStore().getCertificates(null);
                return new ArrayList<X509Certificate>(certs);
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
     * Enrolls the provided CSR into a PKI.
     * 
     * @param csr the certificate signing request
     * @return the enrollment transaction.
     * @throws IOException if any I/O error occurs.
     */
    public Transaction enrol(PKCS10CertificationRequest csr)
            throws IOException {
        LOGGER.debug("Enrolling certificate with CA");
        // TRANSACTIONAL
        // Certificate enrollment
        final Transport transport = createTransport();
        CertStore store = getCaCertificate();
        X509Certificate encryptCert = selectEncryptionCertificate(store);
        X509Certificate verifyCert = selectVerificationCertificate(store);
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                encryptCert);
        PkiMessageEncoder encoder = new PkiMessageEncoder(priKey, identity,
                envEncoder);

        final EnrolmentTransaction t = new EnrolmentTransaction(transport,
                encoder, getDecoder(), csr);
        t.setIssuer(verifyCert);

        return t;
    }

    /**
     * Validates all the input to this client.
     * 
     * @throws NullPointerException if any member variables are null.
     * @throws IllegalArgumentException if any member variables are invalid.
     */
    private void validateInput() throws NullPointerException,
            IllegalArgumentException {
        // Check for null values first.
        if (url == null) {
            throw new NullPointerException("URL should not be null");
        }
        if (identity == null) {
            throw new NullPointerException("Identity should not be null");
        }
        if (priKey == null) {
            throw new NullPointerException("Private key should not be null");
        }
        if (cbh == null) {
            throw new NullPointerException(
                    "Callback handler should not be null");
        }

        if (!identity.getPublicKey().getAlgorithm().equals("RSA")) {
            throw new IllegalArgumentException(
                    "Public key algorithm should be RSA");
        }
        if (!priKey.getAlgorithm().equals("RSA")) {
            throw new IllegalArgumentException(
                    "Private key algorithm should be RSA");
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
    }

    private PkiMessageEncoder getEncoder() throws IOException {
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                getRecipientCertificate());

        return new PkiMessageEncoder(priKey, identity, envEncoder);
    }

    private PkiMessageDecoder getDecoder() {
        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(priKey);

        return new PkiMessageDecoder(envDecoder);
    }

    /**
     * @param issuerCertificate certificate to test
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
     * @return the new transport.
     * @throws IOException if any I/O error occurs.
     */
    private Transport createTransport() throws IOException {
        final Transport t;
        if (getCaCapabilities(true).isPostSupported()) {
            t = Transport.createTransport(Transport.Method.POST, url);
        } else {
            t = Transport.createTransport(Transport.Method.GET, url);
        }

        return t;
    }

    private Capabilities getCaCapabilities(boolean useCache) {
        LOGGER.debug("Determining capabilities of SCEP server");
        // NON-TRANSACTIONAL
        Capabilities caps = null;
        if (useCache) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Retrieving capabilities from cache");
            }
            caps = capabilitiesCache.get(profile);
            if (caps == null) {
                LOGGER.debug("Cache MISS");
            } else {
                LOGGER.debug("Cache HIT");
            }
        }
        if (caps == null) {
            final GetCaCaps req = new GetCaCaps(profile);
            final Transport trans = Transport.createTransport(
                    Transport.Method.GET, url);
            try {
                caps = trans.sendRequest(req,
                        new CaCapabilitiesContentHandler());
            } catch (TransportException e) {
                LOGGER.warn("Transport problem when determining capabilities.  Using empty capabilities.");
                caps = new Capabilities();
            } catch (InvalidContentTypeException e) {
                LOGGER.warn("Transport problem when determining capabilities.  Using empty capabilities.");
                caps = new Capabilities();
            } catch (InvalidContentException e) {
                LOGGER.warn("Transport problem when determining capabilities.  Using empty capabilities.");
                caps = new Capabilities();
            }
            LOGGER.debug("Caching capabilities");
            capabilitiesCache.put(profile, caps);
        }

        return caps;
    }

    private void verifyCA(X509Certificate cert) throws IOException {
        // Cache
        if (verified.contains(cert)) {
            LOGGER.trace("Verification Cache HIT");
            return;
        } else {
            LOGGER.trace("Verification Cache MISS");
        }

        CertificateVerificationCallback callback = new CertificateVerificationCallback(
                cert);
        try {
            LOGGER.debug("Requesting certificate verification.");
            Callback[] callbacks = new Callback[1];
            callbacks[0] = callback;
            cbh.handle(callbacks);
        } catch (UnsupportedCallbackException e) {
            LOGGER.debug("Certificate verification failed.");
            throw new RuntimeException(e);
        }
        if (!callback.isVerified()) {
            LOGGER.debug("Certificate verification failed.");
            throw new IOException(
                    "CA certificate fingerprint could not be verified.");
        } else {
            LOGGER.debug("Certificate verification passed.");
            verified.add(cert);
        }
    }

    private X509Certificate retrieveCA() throws IOException {
        return selectVerificationCertificate(getCaCertificate());
    }

    private X509Certificate getRecipientCertificate() throws IOException {
        final CertStore store = getCaCertificate();
        // The CA or RA
        return selectEncryptionCertificate(store);
    }

    private X509Certificate selectEncryptionCertificate(CertStore store) {
        X509CertificateTuple certPair = X509CertificateTupleFactory
                .createTuple(store);

        return certPair.getEncryption();
    }

    private X509Certificate selectVerificationCertificate(CertStore store) {
        X509CertificateTuple certPair = X509CertificateTupleFactory
                .createTuple(store);

        return certPair.getVerification();
    }

    private X509Certificate selectIssuerCertificate(CertStore store) {
        X509CertificateTuple certPair = X509CertificateTupleFactory
                .createTuple(store);

        return certPair.getIssuer();
    }
}
