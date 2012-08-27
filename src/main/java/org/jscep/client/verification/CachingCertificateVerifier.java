package org.jscep.client.verification;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * This <tt>CertificateVerifier</tt> delegates verification to the provided
 * <tt>CertificateVerifier</tt> and caches the answer.
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
     * This implementation will forward the given certificate to the delegate
     * provided in the constructor, and cache the delegate's response.
     * <p>
     * On every subsequent invocation with the same certificate, the initial
     * response from the delegate will be returned.
     * 
     * @param cert
     *            the certificate to verify.
     * @return the result of calling <tt>verify</tt> on the delegate
     *         <tt>CertificateVerifier</tt>.
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
