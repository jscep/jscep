package org.jscep.client.inspect;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509CertSelector;
import java.util.Arrays;
import java.util.Collection;

/**
 * Default implementation of the <code>CertStoreInspector</code>
 */
final class DefaultCertStoreInspector extends AbstractCertStoreInspector {
	/**
	 * @param store
	 *            the store to inspect
	 */
	DefaultCertStoreInspector(final CertStore store) {
		super(store);
	}

	/**
     * {@inheritDoc}
     */
	protected Collection<X509CertSelector> getIssuerSelectors(byte[] subjectDN) {
		X509CertSelector caSelector = new X509CertSelector();
		caSelector.setBasicConstraints(0);
		try {
            caSelector.setSubject(subjectDN);
		} catch (IOException e) {
            // shut up
        }
		return Arrays.asList(caSelector);
	}

	/**
     * {@inheritDoc}
     */
	protected Collection<X509CertSelector> getSignerSelectors() {
		X509CertSelector digSigSelector = new X509CertSelector();
		digSigSelector.setBasicConstraints(-2);
		digSigSelector.setKeyUsage(new boolean[] { true });

		X509CertSelector caSelector = new X509CertSelector();
		caSelector.setBasicConstraints(0);

		return Arrays.asList(digSigSelector, caSelector);
	}

	/**
     * {@inheritDoc}
     */
	protected Collection<X509CertSelector> getRecipientSelectors() {
		X509CertSelector keyEncSelector = new X509CertSelector();
		keyEncSelector.setBasicConstraints(-2);
		keyEncSelector.setKeyUsage(new boolean[] { false, false, true });

		X509CertSelector dataEncSelector = new X509CertSelector();
		dataEncSelector.setBasicConstraints(-2);
		dataEncSelector
				.setKeyUsage(new boolean[] { false, false, false, true });

		X509CertSelector caSelector = new X509CertSelector();
		caSelector.setBasicConstraints(0);

		return Arrays.asList(keyEncSelector, dataEncSelector, caSelector);
	}
}

