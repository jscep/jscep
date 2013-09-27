package org.jscep.client.inspect;

import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCertStoreInspector implements CertStoreInspector {
	/**
	 * Logger.
	 */
	static final Logger LOGGER = LoggerFactory
			.getLogger(AbstractCertStoreInspector.class);
	protected final CertStore store;
	protected X509Certificate signer;
	protected X509Certificate recipient;
	protected X509Certificate issuer;

	public AbstractCertStoreInspector(CertStore store) {
		this.store = store;

		try {
			inspect();
		} catch (CertStoreException e) {
			throw new RuntimeException(e);
		}
	}

	private void inspect() throws CertStoreException {
		Collection<? extends Certificate> certs = store.getCertificates(null);
		LOGGER.debug("CertStore contains {} certificate(s):", certs.size());
		int i = 0;
		for (Certificate cert : certs) {
			X509Certificate x509 = (X509Certificate) cert;
			LOGGER.debug("{}. '[dn={}; serial={}]'", new Object[] { ++i,
					x509.getSubjectDN(), x509.getSerialNumber() });
		}

		LOGGER.debug("Looking for recipient entity");
		recipient = selectCertificate(store, getRecipientSelectors());
		LOGGER.debug("Using [dn={}; serial={}] for recipient entity",
				recipient.getSubjectDN(), recipient.getSerialNumber());

		LOGGER.debug("Looking for message signing entity");
		signer = selectCertificate(store, getSignerSelectors());
		LOGGER.debug("Using [dn={}; serial={}] for message signing entity",
				signer.getSubjectDN(), signer.getSerialNumber());

		LOGGER.debug("Looking for issuing entity");
		issuer = selectCertificate(store, getIssuerSelectors(recipient.getIssuerX500Principal().getEncoded()));
		LOGGER.debug("Using [dn={}; serial={}] for issuing entity",
				issuer.getSubjectDN(), issuer.getSerialNumber());
	}

	/**
	 * Finds the certificate of the SCEP message object recipient.
	 * 
	 * @param store
	 *            the certificate store to inspect.
	 * @return the recipient's certificate.
	 * @throws CertStoreException
	 *             if the CertStore cannot be inspected
	 */
	X509Certificate selectCertificate(final CertStore store,
			final Collection<X509CertSelector> selectors) throws CertStoreException {
		for (CertSelector selector : selectors) {
			LOGGER.debug("Selecting certificate using {}", selector);
			Collection<? extends Certificate> certs = store
					.getCertificates(selector);
			if (certs.size() > 0) {
				LOGGER.debug("Selected {} certificate(s) using {}",
						certs.size(), selector);
				return (X509Certificate) certs.iterator().next();
			} else {
				LOGGER.debug("No certificates selected");
			}
		}
		return (X509Certificate) store.getCertificates(null).iterator().next();
	}

	protected abstract Collection<X509CertSelector> getIssuerSelectors(byte[] issuerDN);

	protected abstract Collection<X509CertSelector> getSignerSelectors();

	protected abstract Collection<X509CertSelector> getRecipientSelectors();

	/**
	 * {@inheritDoc}
	 */
	public final X509Certificate getSigner() {
		return signer;
	}

	/**
	 * {@inheritDoc}
	 */
	public final X509Certificate getRecipient() {
		return recipient;
	}

	/**
	 * {@inheritDoc}
	 */
	public final X509Certificate getIssuer() {
		return issuer;
	}

}
