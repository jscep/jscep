package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.cert.CertStore;

import org.bouncycastle.asn1.cms.SignedData;

public interface DegenerateSignedData {
	CertStore getCertStore();
	public byte[] getEncoded() throws IOException;
	public SignedData getContent();
}
