package org.jscep.client;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Authorities {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(Authorities.class);
    private static final int KEY_USAGE_LENGTH = 9;
    private static final int DIGITAL_SIGNATURE = 0;
    private static final int KEY_ENCIPHERMENT = 2;
    private static final int DATA_ENCIPHERMENT = 3;

    private final X509Certificate verifier;
    private final X509Certificate encrypter;
    private final X509Certificate issuer;

    public Authorities(X509Certificate verifier,
            X509Certificate encrypter, X509Certificate issuer) {
        this.verifier = verifier;
        this.encrypter = encrypter;
        this.issuer = issuer;
    }

    public X509Certificate getVerifier() {
        return verifier;
    }

    public X509Certificate getEncrypter() {
        return encrypter;
    }

    public X509Certificate getIssuer() {
        return issuer;
    }

    public static Authorities fromCertStore(CertStore store) {
        try {
            Collection<? extends Certificate> certs = store
                    .getCertificates(null);
            LOGGER.debug("CertStore contains {} certificate(s):", certs.size());
            int i = 0;
            for (Certificate cert : certs) {
                X509Certificate x509 = (X509Certificate) cert;
                LOGGER.debug("{}. '{}'", ++i, x509.getSubjectDN());
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        X509Certificate encryption = selectEncryptionCertificate(store);
        LOGGER.debug("Using {} for message encryption",
                encryption.getSubjectDN());

        X509Certificate signing = selectMessageVerifier(store);
        LOGGER.debug("Using {} for message verification",
                signing.getSubjectDN());

        X509Certificate issuer = selectIssuerCertificate(store);
        LOGGER.debug("Using {} for issuer", signing.getSubjectDN());

        return new Authorities(signing, encryption, issuer);
    }

    private static X509Certificate selectIssuerCertificate(CertStore store) {
        LOGGER.debug("Selecting issuer certificate");

        try {
            LOGGER.debug("Selecting certificate with basicConstraints");
            return getCaCertificate(store);
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate selectMessageVerifier(CertStore store) {
        LOGGER.debug("Selecting verifier certificate");
        X509CertSelector signingSelector = new X509CertSelector();
        boolean[] keyUsage = new boolean[KEY_USAGE_LENGTH];
        keyUsage[DIGITAL_SIGNATURE] = true;
        signingSelector.setKeyUsage(keyUsage);

        try {
            LOGGER.debug("Selecting certificate with digitalSignature keyUsage");
            Collection<? extends Certificate> certs = store
                    .getCertificates(signingSelector);
            if (certs.size() > 0) {
                return (X509Certificate) certs.iterator().next();
            } else {
                LOGGER.debug("No certificates found.  Falling back to CA certificate");
                return getCaCertificate(store);
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate getCaCertificate(CertStore store)
            throws CertStoreException {
        X509CertSelector selector = new X509CertSelector();
        selector.setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
        selector.setBasicConstraints(0);

        Collection<? extends Certificate> certs = store
                .getCertificates(selector);
        if (certs.size() > 0) {
            return (X509Certificate) certs.iterator().next();
        } else {
            throw new RuntimeException(
                    "No suitable certificate for verification");
        }
    }

    private static X509Certificate selectEncryptionCertificate(CertStore store) {
        LOGGER.debug("Selecting encryption certificate");
        X509CertSelector signingSelector = new X509CertSelector();
        boolean[] keyUsage = new boolean[KEY_USAGE_LENGTH];
        keyUsage[KEY_ENCIPHERMENT] = true;
        signingSelector.setKeyUsage(keyUsage);

        try {
            LOGGER.debug("Selecting certificate with keyEncipherment keyUsage");
            Collection<? extends Certificate> certs = store
                    .getCertificates(signingSelector);
            if (certs.size() > 0) {
                return (X509Certificate) certs.iterator().next();
            }

            LOGGER.debug("No certificates found.  Selecting certificate with dataEncipherment keyUsage");
            keyUsage = new boolean[KEY_USAGE_LENGTH];
            keyUsage[DATA_ENCIPHERMENT] = true;
            signingSelector.setKeyUsage(keyUsage);

            certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                return (X509Certificate) certs.iterator().next();
            }

            LOGGER.debug("No certificates found.  Falling back to CA certificate");
            return getCaCertificate(store);
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
