package com.google.code.jscep.util;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.SignedData;

public final class SignedDataUtil {
	public static CertStore extractCertStore(SignedData signedData) throws GeneralSecurityException {
		final CertificateFactory factory = CertificateFactory.getInstance("X.509");
		final Collection<Object> collection = new HashSet<Object>();
		final ASN1Set certs = signedData.getCertificates();
		final ASN1Set crls = signedData.getCRLs();
		
		if (certs != null) {
			final Enumeration<?> certEnum = certs.getObjects();
			while (certEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) certEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				Certificate cert = factory.generateCertificate(bais);
				collection.add(cert);
			}
		}
		if (crls != null) {
			final Enumeration<?> crlEnum = crls.getObjects();
			while (crlEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) crlEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				CRL crl = factory.generateCRL(bais);
				collection.add(crl);
			}
		}
		
		final CertStoreParameters parameters = new CollectionCertStoreParameters(collection);
		return CertStore.getInstance("Collection", parameters);
	}
}
