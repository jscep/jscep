package org.jscep.client.verification;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * This <tt>CertificateVerifier</tt> implementation delegates verification to
 * the provided <tt>CertificateVerifier</tt> and caches the answer.
 */
public final class CachingCertificateVerifier implements CertificateVerifier {
    private final Map<Certificate, Boolean> verificationAnswers;
    private final CertificateVerifier delegate;

    /**
     * Constructs a <tt>CachingCertificateVerifier</tt> which delegates to the
     * specified <tt>CertificateVerifier</tt>.
     * 
     * @param delegate
     *            the <tt>CertificateVerifier</tt> to delegate to.
     */
    public CachingCertificateVerifier(final CertificateVerifier delegate) {
        this.delegate = delegate;
        this.verificationAnswers = new HashMap<Certificate, Boolean>();
    }

    /**
     * This implementation will verify the provided certificate with the
     * delegate provided to the constructor and cache the response.
     * <p>
     * On subsequent invocations, the initial response from the delegate will be
     * replayed.
     * <p>
     * {@inheritDoc}
     */
    public synchronized boolean verify(final X509Certificate cert) {
        if (verificationAnswers.containsKey(cert)) {
            return verificationAnswers.get(cert);
        } else {
            boolean answer = delegate.verify(cert);
            verificationAnswers.put(cert, answer);

            return answer;
        }
    }

}
