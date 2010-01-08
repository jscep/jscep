package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private CertStore store;
	
	public void setCertStore(CertStore store) {
		this.store = store;
	}
	
	public DegenerateSignedData generate() throws IOException {
		LOGGER.entering(getClass().getName(), "generate");
		
		DERInteger version = new DERInteger(1);
		DERSet digestAlgorithms = new DERSet();
		ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new byte[0]));
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
		} catch (CertStoreException e) {
			LOGGER.throwing(getClass().getName(), "generate", e);
			throw new RuntimeException(e);
		} catch (GeneralSecurityException e) {
			LOGGER.throwing(getClass().getName(), "generate", e);
			throw new RuntimeException(e);
		}
		DERSet certificates = new DERSet(certVector);
		DERSet crls = new DERSet(crlVector);
		
		SignedData sd = new SignedData(version, digestAlgorithms, contentInfo, certificates, crls, signerInfos);
		
		DegenerateSignedDataImpl dsd =new DegenerateSignedDataImpl();
		dsd.setCertStore(store);
		dsd.setEncoded(sd.getDEREncoded());
		
		LOGGER.exiting(getClass().getName(), "generate");
		return dsd;
	}
}
