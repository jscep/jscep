package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private CertStore store;
	
	public void setCertStore(CertStore store) {
		this.store = store;
	}
	
	public DegenerateSignedData generate() throws IOException {
		LOGGER.entering(getClass().getName(), "generate");
		
		DERSet digestAlgorithms = new DERSet();
		ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(new byte[0]));
		DERSet signerInfos = new DERSet();
		DEREncodableVector certVector = new ASN1EncodableVector();
		DEREncodableVector crlVector = new ASN1EncodableVector();
		try {
			Collection<? extends Certificate> certs = store.getCertificates(new X509CertSelector());
			for (Certificate cert : certs) {
				certVector.add(ASN1Object.fromByteArray(cert.getEncoded()));
			}
			Collection<? extends CRL> crls = store.getCRLs(new X509CRLSelector());
			for (CRL crl : crls) {
				X509CRL x509crl = (X509CRL) crl;
				crlVector.add(ASN1Object.fromByteArray(x509crl.getEncoded()));
			}
		} catch (GeneralSecurityException e) {
			LOGGER.throwing(getClass().getName(), "generate", e);
			throw new RuntimeException(e);
		}
		DERSet certificates = new DERSet(certVector);
		DERSet crls = new DERSet(crlVector);
		
		SignedData sd = new SignedData(digestAlgorithms, contentInfo, certificates, crls, signerInfos);
		DegenerateSignedData dsd = new DegenerateSignedDataImpl(sd);
		
		LOGGER.exiting(getClass().getName(), "generate", dsd);
		return dsd;
	}
}
