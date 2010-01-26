package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

public class DegenerateSignedData {
	private final CertStore certStore;
	private final byte[] encoded;
	
	DegenerateSignedData(CertStore store, byte[] encoded) {
		this.certStore = store;
		this.encoded = encoded;
	}
	
	public byte[] getEncoded() {
		return encoded;
	}
	
	public CertStore getCertStore() {
		return certStore;
	}
}
