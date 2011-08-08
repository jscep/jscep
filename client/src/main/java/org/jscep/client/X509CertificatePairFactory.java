package org.jscep.client;

import java.security.cert.*;
import java.util.Collection;

public class X509CertificatePairFactory {
    public static X509CertificatePair createPair(CertStore store) {
        X509Certificate signing;
        X509Certificate encryption;

        X509CertSelector signingSelector = new X509CertSelector();
        boolean[] keyUsage = new boolean[9];
        keyUsage[3] = true;
        signingSelector.setKeyUsage(keyUsage);

        try {
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                signing = (X509Certificate) certs.iterator().next();
            } else {
                keyUsage[3] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                signing = (X509Certificate) certs.iterator().next();
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        keyUsage[3] = false;
        keyUsage[0] = true;
        signingSelector.setKeyUsage(keyUsage);

        try {
            Collection<? extends Certificate> certs = store.getCertificates(signingSelector);
            if (certs.size() > 0) {
                encryption = (X509Certificate) certs.iterator().next();
            } else {
                keyUsage[0] = false;
                signingSelector.setKeyUsage(keyUsage);
                signingSelector.setBasicConstraints(0);

                certs = store.getCertificates(signingSelector);
                encryption = (X509Certificate) certs.iterator().next();
            }
        } catch (CertStoreException e) {
            throw new RuntimeException(e);
        }

        return new X509CertificatePair(signing, encryption);
    }
}
