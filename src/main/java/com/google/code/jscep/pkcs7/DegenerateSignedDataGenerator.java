package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.cert.CertStore;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
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
