package org.jscep.client;

import java.security.cert.*;
import java.util.Collection;

public class X509CertificatePairFactory {
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
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                encryption = (X509Certificate) certs.iterator().next();
            } else {
                keyUsage[DATA_ENCIPHERMENT] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                encryption = (X509Certificate) certs.iterator().next();
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        keyUsage[DATA_ENCIPHERMENT] = false;
        keyUsage[DIGITAL_SIGNATURE] = true;
        signingSelector.setKeyUsage(keyUsage);
        signingSelector.setBasicConstraints(-1);

        try {
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                signing = (X509Certificate) certs.iterator().next();
            } else {
                keyUsage[DIGITAL_SIGNATURE] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                signing = (X509Certificate) certs.iterator().next();
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        return new X509CertificatePair(signing, encryption);
    }
}
