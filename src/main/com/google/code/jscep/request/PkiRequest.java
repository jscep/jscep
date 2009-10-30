package com.google.code.jscep.request;

import java.io.IOException;

import org.bouncycastle.cms.CMSSignedData;

public class PkiRequest implements Request {
	private static final String OPERATION = "PKIOperation";
	private final CMSSignedData signedData;
	
	public PkiRequest(CMSSignedData signedData) {
		this.signedData = signedData;
	}

	@Override
	public Object getMessage() throws IOException {
		return signedData.getEncoded();
	}

	@Override
	public String getOperation() {
		return OPERATION;
	}

}
