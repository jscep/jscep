package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * This <tt>CertificateVerifier</tt> always returns <tt>false</tt>.
 * <p>
 * This implementation is primarily used for testing, although it can also be
 * used for disabling your SCEP client.
 */
public final class PessimisticCertificateVerifier implements
	CertificateVerifier {
    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
	return false;
    }

}
