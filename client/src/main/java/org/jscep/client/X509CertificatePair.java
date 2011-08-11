package org.jscep.client;

import java.security.cert.X509Certificate;

public class X509CertificatePair {
    private final X509Certificate verification;
    private final X509Certificate encryption;

    public X509CertificatePair(X509Certificate verification, X509Certificate encryption) {
        this.verification = verification;
        this.encryption = encryption;
    }

    public X509Certificate getVerification() {
        return verification;
    }

    public X509Certificate getEncryption() {
        return encryption;
    }
}
