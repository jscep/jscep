package com.google.code.jscep.pkcs7;

import java.security.cert.CertStore;

public interface DegenerateSignedData {
	CertStore getCertStore();
	byte[] getEncoded();
}
