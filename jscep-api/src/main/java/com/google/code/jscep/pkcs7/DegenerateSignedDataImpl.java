package com.google.code.jscep.pkcs7;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

class DegenerateSignedDataImpl extends ContentInfo implements DegenerateSignedData {
	DegenerateSignedDataImpl(SignedData data) {
		super(CMSObjectIdentifiers.signedData, data);
	}
	
	@Override
	public SignedData getContent() {
		return (SignedData) super.getContent();
	}
	
	public CertStore getCertStore() {
		final List backing = new ArrayList();
		
		try {
			backing.addAll(getCertificates());
			backing.addAll(getCRLs());
			final CertStoreParameters params = new CollectionCertStoreParameters(backing);
			
			return CertStore.getInstance("Collection", params);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private Collection<Certificate> getCertificates() throws GeneralSecurityException {
		final List<Certificate> x509s = new ArrayList<Certificate>();
		final CertificateFactory factory = CertificateFactory.getInstance("X.509");
		
		if (getContent().getCertificates() != null) {
			final Enumeration<?> certs = getContent().getCertificates().getObjects();
			while (certs.hasMoreElements()) {
				ASN1Sequence seq = (ASN1Sequence) certs.nextElement();
				ByteArrayInputStream bIn = new ByteArrayInputStream(seq.getDEREncoded());
				x509s.add(factory.generateCertificate(bIn));
			}
		}
		
		return x509s;
	}
	
	private Collection<CRL> getCRLs() throws GeneralSecurityException {
		List<CRL> x509s = new ArrayList<CRL>();
		final CertificateFactory factory = CertificateFactory.getInstance("X.509");
		
		if (getContent().getCRLs() != null) {
			final Enumeration<?> crls = getContent().getCRLs().getObjects();
			while (crls.hasMoreElements()) {
				ASN1Sequence seq = (ASN1Sequence) crls.nextElement();
				ByteArrayInputStream bIn = new ByteArrayInputStream(seq.getDEREncoded());
				x509s.add(factory.generateCRL(bIn));
			}
		}
		
		return x509s;
	}
}
