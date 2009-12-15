package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSSignedData;

public final class CertRepImpl extends CertRep {
	private final byte[] signedData;
	
	public CertRepImpl(byte[] signedData) {
		this.signedData = signedData;
	}
	
	public CertStore getCertStore() {
		try {
			CMSSignedData sd = new CMSSignedData(signedData);
			return sd.getCertificatesAndCRLs("Collection", "BC");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
