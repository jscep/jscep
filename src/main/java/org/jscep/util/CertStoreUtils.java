package org.jscep.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used for performing utility operations for <tt>CertStore</tt>s.
 */
public final class CertStoreUtils {
    private static final Logger LOGGER = LoggerFactory
	    .getLogger(CertStoreUtils.class);

    /**
     * Disallow instance creation.
     */
    private CertStoreUtils() {
    }

    /**
     * Converts a Bouncy Castle <tt>signedData</tt> object into a
     * <tt>CertStore</tt>.
     * <p>
     * This method will extract all certificates and CRLs from the
     * <tt>signedData</tt>. It makes <strong>no</strong> attempt to verify the
     * integrity of the <tt>signedData</tt>.
     * 
     * @param signedData
     *            the <tt>signedData</tt> to etract.
     * @return the extracted certificates and CRLs.
     */
    @SuppressWarnings("unchecked")
    public static CertStore fromSignedData(CMSSignedData signedData) {
	// TODO: Move to SignedDataUtil.
	CertificateFactory factory;
	try {
	    factory = CertificateFactory.getInstance("X509");
	} catch (CertificateException e) {
	    throw new RuntimeException(e);
	}

	Store certStore = signedData.getCertificates();
	Store crlStore = signedData.getCRLs();

	Collection<X509CertificateHolder> certs = certStore.getMatches(null);
	Collection<X509CRLHolder> crls = crlStore.getMatches(null);

	Collection<Object> certsAndCrls = new ArrayList<Object>();

	for (X509CertificateHolder cert : certs) {
	    ByteArrayInputStream byteIn;
	    try {
		byteIn = new ByteArrayInputStream(cert.getEncoded());
	    } catch (IOException e) {
		LOGGER.error("Error encoding certificate", e);

		continue;
	    }
	    try {
		certsAndCrls.add(factory.generateCertificate(byteIn));
	    } catch (CertificateException e) {
		LOGGER.error("Error generating certificate", e);
	    }
	}

	for (X509CRLHolder crl : crls) {
	    ByteArrayInputStream byteIn;
	    try {
		byteIn = new ByteArrayInputStream(crl.getEncoded());
	    } catch (IOException e) {
		LOGGER.error("Error encoding crl", e);

		continue;
	    }
	    try {
		certsAndCrls.add(factory.generateCRL(byteIn));
	    } catch (CRLException e) {
		LOGGER.error("Error generating certificate", e);
	    }
	}

	try {
	    return CertStore.getInstance("Collection",
		    new CollectionCertStoreParameters(certsAndCrls));
	} catch (GeneralSecurityException e) {
	    throw new RuntimeException(e);
	}
    }
}
