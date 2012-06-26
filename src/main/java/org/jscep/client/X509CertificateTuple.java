package org.jscep.client;

import java.security.cert.X509Certificate;

public class X509CertificateTuple {
    private final X509Certificate verification;
    private final X509Certificate encryption;
    private final X509Certificate issuer;

    public X509CertificateTuple(X509Certificate verification,
            X509Certificate encryption, X509Certificate issuer) {
        this.verification = verification;
        this.encryption = encryption;
        this.issuer = issuer;
    }

    public X509Certificate getVerification() {
        return verification;
    }

    public X509Certificate getEncryption() {
        return encryption;
    }

    public X509Certificate getIssuer() {
        return issuer;
    }
}
