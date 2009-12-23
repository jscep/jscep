package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;
import java.util.logging.Logger;

import com.google.code.jscep.util.LoggingUtil;

class DegenerateSignedDataImpl implements DegenerateSignedData {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
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
