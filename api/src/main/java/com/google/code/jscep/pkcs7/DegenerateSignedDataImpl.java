package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

class DegenerateSignedDataImpl implements DegenerateSignedData {
	private final CertStore certStore;
	private final byte[] encoded;
	
	DegenerateSignedDataImpl(CertStore store, byte[] encoded) {
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
