package org.jscep.client.inspect;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the <code>CertStoreInspector</code> for Apache Harmony (Android)
 */
final class HarmonyCertStoreInspector implements CertStoreInspector {
    /**
     * The length of the minimum certificate path for an issuer.
     */
    private static final int CA_PATH_LENGTH = 0;
    /**
     * Logger.
     */
    static final Logger LOGGER = LoggerFactory
            .getLogger(HarmonyCertStoreInspector.class);
    /**
     * Length of the key usage array.
     */
    private static final int KEY_USAGE_LENGTH = 9;

    private final CertStore store;
    private X509Certificate signer;
    private X509Certificate recipient;
    private X509Certificate issuer;

    /**
     * @param signer
     *            the certificate of the message signing authority
     * @param recipient
     *            the certificate of the message recipient.
     * @param issuer
     *            the certificate of the certificate issuer.
     */
    HarmonyCertStoreInspector(final CertStore store) {
        this.store = store;

        try {
            inspect();
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private void inspect() throws CertStoreException {
        Collection<? extends Certificate> certs = store.getCertificates(null);
        LOGGER.debug("CertStore contains {} certificate(s):", certs.size());
        int i = 0;
        for (Certificate cert : certs) {
            X509Certificate x509 = (X509Certificate) cert;
            LOGGER.debug("{}. '[issuer={}; serial={}]'", new Object[] { ++i,
                    x509.getIssuerDN(), x509.getSerialNumber() });
        }

        LOGGER.debug("Looking for recipient entity");
        recipient = findRecipient(store);
        LOGGER.debug("Using [issuer={}; serial={}] for recipient entity",
                recipient.getIssuerDN(), recipient.getSerialNumber());

        LOGGER.debug("Looking for message signing entity");
        signer = findSigner(store);
        LOGGER.debug("Using [issuer={}; serial={}] for message signing entity",
                signer.getIssuerDN(), signer.getSerialNumber());

        LOGGER.debug("Looking for issuing entity");
        issuer = findIssuer(store);
        LOGGER.debug("Using [issuer={}; serial={}] for issuing entity",
                issuer.getIssuerDN(), issuer.getSerialNumber());
    }

    /*
     * (non-Javadoc)
     * @see org.jscep.client.inspect.CertStoreInspector#getSigner()
     */
    @Override
    public X509Certificate getSigner() {
        return signer;
    }

    /*
     * (non-Javadoc)
     * @see org.jscep.client.inspect.CertStoreInspector#getRecipient()
     */
    @Override
    public X509Certificate getRecipient() {
        return recipient;
    }

    /*
     * (non-Javadoc)
     * @see org.jscep.client.inspect.CertStoreInspector#getIssuer()
     */
    @Override
    public X509Certificate getIssuer() {
        return issuer;
    }

    /**
     * Finds the certificate of the certificate issuer.
     *
     * @param store
     *            the certificate store to inspect.
     * @return the certificate issuer's certificate.
     * @throws CertStoreException
     *             if the CertStore cannot be inspected
     */
    X509Certificate findIssuer(final CertStore store)
            throws CertStoreException {
        X509CertSelector selector = new X509CertSelector();
        selector.setBasicConstraints(CA_PATH_LENGTH);

        LOGGER.debug("Selecting certificate with basicConstraints pathLen > 0");
        Collection<? extends Certificate> certs = store
                .getCertificates(selector);
        if (certs.size() > 0) {
            LOGGER.debug(
                    "Found {} certificate(s) with basicConstraints pathLen > 0",
                    certs.size());
            return (X509Certificate) certs.iterator().next();
        } else {
            throw new RuntimeException("No CA certificates found");
        }
    }

    /**
     * Finds the certificate of the SCEP message object signer.
     *
     * @param store
     *            the certificate store to inspect.
     * @return the signer's certificate.
     * @throws CertStoreException
     *             if the CertStore cannot be inspected
     */
    X509Certificate findSigner(final CertStore store)
            throws CertStoreException {
        boolean[] keyUsage = new boolean[KEY_USAGE_LENGTH];
        keyUsage[0] = true;
        X509CertSelector signingSelector = new X509CertSelector();
        signingSelector.setKeyUsage(keyUsage);

        LOGGER.debug("Selecting certificate with keyUsage:digitalSignature");
        Collection<? extends Certificate> certs = store
                .getCertificates(signingSelector);
        if (certs.size() > 0) {
            LOGGER.debug(
                    "Found {} certificate(s) with keyUsage:digitalSignature",
                    certs.size());
            return (X509Certificate) certs.iterator().next();
        } else {
            LOGGER.debug("No certificates found.");
        }
        return findIssuer(store);
    }

    /**
     * Finds the certificate of the SCEP message object recipient.
     *
     * @param store
     *            the certificate store to inspect.
     * @return the recipient's certificate.
     * @throws CertStoreException
     *             if the CertStore cannot be inspected
     */
    X509Certificate findRecipient(final CertStore store)
            throws CertStoreException {
        boolean[] keyUsage = new boolean[KEY_USAGE_LENGTH];
        keyUsage[2] = true;
        X509CertSelector signingSelector = new X509CertSelector();
        signingSelector.setKeyUsage(keyUsage);

        LOGGER.debug("Selecting certificate with keyUsage:keyEncipherment");
        Collection<? extends Certificate> certs = store
                .getCertificates(signingSelector);
        if (certs.size() > 0) {
            LOGGER.debug(
                    "Found {} certificate(s) with keyUsage:keyEncipherment",
                    certs.size());
            return (X509Certificate) certs.iterator().next();
        } else {
            LOGGER.debug("No certificates found.");
        }

        LOGGER.debug("Selecting certificate with keyUsage:dataEncipherment");
        keyUsage = new boolean[KEY_USAGE_LENGTH];
        keyUsage[3] = true;
        signingSelector.setKeyUsage(keyUsage);

        certs = store.getCertificates(signingSelector);
        if (certs.size() > 0) {
            LOGGER.debug(
                    "Found {} certificate(s) with keyUsage:dataEncipherment",
                    certs.size());
            return (X509Certificate) certs.iterator().next();
        } else {
            LOGGER.debug("No certificates found");
        }

        return findIssuer(store);
    }
}
