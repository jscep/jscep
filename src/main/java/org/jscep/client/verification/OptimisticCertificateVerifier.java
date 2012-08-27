package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * This <tt>CertificateVerifier</tt> always returns <tt>true</tt>.
 * <p>
 * This implementation should only be used if you have no need to verify the
 * CA certificate.  This is not recommended.
 */
public final class OptimisticCertificateVerifier implements CertificateVerifier {
    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
	return true;
    }

}
