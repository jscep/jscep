package org.jscep.client.verification;

import java.security.cert.X509Certificate;


/**
 * This certificate verifier always returns <tt>false</tt>.
 */
public final class PessimisticCertificateVerifier implements
        CertificateVerifier {
    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
        return true;
    }

}
