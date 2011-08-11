package org.jscep.client;

import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.security.cert.*;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateTupleFactory {
    private static Logger LOGGER = LoggingUtil.getLogger(X509CertificateTupleFactory.class);
    private static Map<CertStore, X509CertificateTuple> cache = new HashMap<CertStore, X509CertificateTuple>();
    public static final int DIGITAL_SIGNATURE = 0;
    public static final int DATA_ENCIPHERMENT = 3;

    public static X509CertificateTuple createTuple(CertStore store) {
        if (cache.containsKey(store)) {
            LOGGER.debug("{} has already been inspected, retrieving result from cache.", store);
            return cache.get(store);
        } else if (cache.isEmpty() == false) {
            LOGGER.debug("Cache missed, so clearing");
            cache.clear();
        }
        try {
            Collection<? extends Certificate> certs = store.getCertificates(null);
            LOGGER.debug("CertStore contains {} certificate(s):", certs.size());
            int i = 0;
            for (Certificate cert : certs) {
                X509Certificate x509 = (X509Certificate) cert;
                LOGGER.debug("{}. '{}'", ++i, x509.getSubjectDN());
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        X509Certificate signing;
        X509Certificate encryption;
        X509Certificate issuer;

        X509CertSelector signingSelector = new X509CertSelector();
        boolean[] keyUsage = new boolean[9];
        keyUsage[DATA_ENCIPHERMENT] = true;
        signingSelector.setKeyUsage(keyUsage);

        try {
            LOGGER.debug("Selecting certificate with dataEncipherment keyUsage");
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                encryption = (X509Certificate) certs.iterator().next();
            } else {
                LOGGER.debug("No certificates found.  Falling back to CA certificate");
                keyUsage[DATA_ENCIPHERMENT] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                if (certs.size() > 0) {
                    encryption = (X509Certificate) certs.iterator().next();
                } else {
                    throw new RuntimeException("No suitable certificate for encryption");
                }
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
        LOGGER.debug("Using {} for message encryption", encryption.getSubjectDN());

        keyUsage[DATA_ENCIPHERMENT] = false;
        keyUsage[DIGITAL_SIGNATURE] = true;
        signingSelector.setKeyUsage(keyUsage);
        signingSelector.setBasicConstraints(-1);

        try {
            LOGGER.debug("Selecting certificate with digitalSignature keyUsage");
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                signing = (X509Certificate) certs.iterator().next();
            } else {
                LOGGER.debug("No certificates found.  Falling back to CA certificate");
                keyUsage[DIGITAL_SIGNATURE] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                if (certs.size() > 0) {
                    signing = (X509Certificate) certs.iterator().next();
                } else {
                    throw new RuntimeException("No suitable certificate for verification");
                }
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
        LOGGER.debug("Using {} for message verification", signing.getSubjectDN());

        keyUsage[DIGITAL_SIGNATURE] = false;
        signingSelector.setKeyUsage(keyUsage);
        signingSelector.setBasicConstraints(0);
        LOGGER.debug("Selecting certificate with basicConstraints");
        try {
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                issuer = (X509Certificate) certs.iterator().next();
            } else {
                throw new RuntimeException("No suitable certificate for verification");
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        X509CertificateTuple pair = new X509CertificateTuple(signing, encryption, issuer);
        cache.put(store, pair);

        return pair;
    }
}
