package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

public abstract class CertRep {
	public abstract CertStore getCertStore();
	
	public static CertRep getInstance(byte[] signedData) {
		return new CertRepImpl(signedData);
	}
}
