package org.jscep.client.verification;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;


/**
 * CertificateVerifier that uses a known message digest to verify the
 * certificate.
 */
public final class MessageDigestCertificateVerifier implements
        CertificateVerifier {
    /**
     * The digest to use.
     */
    private final MessageDigest digest;
    /**
     * The expected digest outcome.
     */
    private final byte[] expected;

    /**
     * Creates a new instance with a digest algorithm, and the expected digest
     * result.
     * 
     * @param digest the digest algorithm to use to verify.
     * @param expected the digest result
     */
    public MessageDigestCertificateVerifier(MessageDigest digest,
            byte[] expected) {
        this.digest = digest;
        this.expected = expected;
    }

    /**
     * {@inheritDoc}
     */
    public boolean verify(final X509Certificate cert) {
        byte[] actual;
        try {
            digest.reset();
            actual = digest.digest(cert.getTBSCertificate());
        } catch (CertificateEncodingException e) {
            return false;
        }

        return Arrays.equals(actual, expected);
    }
}
