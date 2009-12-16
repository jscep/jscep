package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

public class DegenerateSignedDataGenerator {
	private CertStore store;
	
	public void setCertStore(CertStore store) {
		this.store = store;
	}
	
	public DegenerateSignedData generate() {
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		try {
			generator.addCertificatesAndCRLs(store);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		CMSProcessable processable = new CMSProcessableByteArray(new byte[0]);
		CMSSignedData signedData;
		try {
			signedData = generator.generate(processable, "BC");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		DegenerateSignedDataImpl dsd =new DegenerateSignedDataImpl();
		dsd.setCertStore(store);
		try {
			dsd.setEncoded(signedData.getEncoded());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		return dsd;
	}
}
