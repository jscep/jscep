package org.jscep.client;

import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.security.cert.*;
import java.util.Collection;

public class X509CertificatePairFactory {
    private static Logger LOGGER = LoggingUtil.getLogger(X509CertificatePairFactory.class);
    public static final int DIGITAL_SIGNATURE = 0;
    public static final int DATA_ENCIPHERMENT = 3;

    public static X509CertificatePair createPair(CertStore store) {
        X509Certificate signing;
        X509Certificate encryption;

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
                encryption = (X509Certificate) certs.iterator().next();
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
                signing = (X509Certificate) certs.iterator().next();
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }
        LOGGER.debug("Using {} for message verification", signing.getSubjectDN());

        return new X509CertificatePair(signing, encryption);
    }
}
