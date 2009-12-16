package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSSignedData;

public class DegenerateSignedDataParser {
	public DegenerateSignedData parse(byte[] signedData) throws IOException {
		try {
			CMSSignedData sd = new CMSSignedData(signedData);
			CertStore store = sd.getCertificatesAndCRLs("Collection", "BC");
			
			DegenerateSignedDataImpl certRep = new DegenerateSignedDataImpl();
			certRep.setCertStore(store);
			certRep.setEncoded(signedData);
			
			return certRep;
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
