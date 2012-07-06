package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * CertificateVerifier that uses a pre-provisioned certificate.
 */
public final class PreProvisionedCertificateVerifier implements
        CertificateVerifier {
    /**
     * The pre-provisioned certificate.
     */
    private final X509Certificate cert;

    /**
     * Creates a new instance of this class with a pre-provisioned certificate.
     * 
     * @param cert
     *            the pre-provisioned certificate.
     */
    public PreProvisionedCertificateVerifier(X509Certificate cert) {
        this.cert = cert;
    }

    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
        return this.cert.equals(cert);
    }

}
