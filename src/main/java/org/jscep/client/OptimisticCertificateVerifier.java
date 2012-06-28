package org.jscep.client;

import java.security.cert.X509Certificate;

/**
 * This certificate verifier always verifies certificates as valid.
 */
public final class OptimisticCertificateVerifier implements CertificateVerifier {
    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
        return true;
    }

}
