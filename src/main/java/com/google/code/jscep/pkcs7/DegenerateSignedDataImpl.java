package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

class DegenerateSignedDataImpl implements DegenerateSignedData {
	private CertStore certStore;
	private byte[] encoded;
	
	void setCertStore(CertStore certStore) {
		this.certStore = certStore;
	}
	
	void setEncoded(byte[] encoded) {
		this.encoded = encoded;
	}
	
	public byte[] getEncoded() {
		return encoded;
	}
	
	public CertStore getCertStore() {
		return certStore;
	}
}
