package org.jscep.client;

import java.security.cert.X509Certificate;

public class X509CertificatePair {
    private final X509Certificate signing;
    private final X509Certificate encryption;

    public X509CertificatePair(X509Certificate signing, X509Certificate encryption) {
        this.signing = signing;
        this.encryption = encryption;
    }

    public X509Certificate getSigning() {
        return signing;
    }

    public X509Certificate getEncryption() {
        return encryption;
    }
}
