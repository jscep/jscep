package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * Interface for verifying the identity of a given certificate.
 */
public interface CertificateVerifier {
    /**
     * Verifies the certificate.
     * 
     * @param cert the certificate to verify.
     * @return <tt>true</tt> if the identity of the certificate can be verified,
     *         <tt>false</tt> otherwise.
     */
    boolean verify(X509Certificate cert);
}
