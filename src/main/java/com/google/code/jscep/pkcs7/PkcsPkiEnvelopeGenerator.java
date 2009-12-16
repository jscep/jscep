package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;

import com.google.code.jscep.transaction.CmsException;

public class PkcsPkiEnvelopeGenerator {
	private X509Certificate recipient;
	private String cipher;
	
	public void setRecipient(X509Certificate recipient) {
		this.recipient = recipient;
	}
	
	public void setCipher(String cipher) {
		this.cipher = cipher;
	}
	
	public PkcsPkiEnvelope generate(byte[] messageData) throws CmsException, GeneralSecurityException, IOException {
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    	gen.addKeyTransRecipient(recipient);
    	CMSProcessable processableData = new CMSProcessableByteArray(messageData);
    	CMSEnvelopedData envelopedData;
		try {
			// Need BC Provider Here.
			envelopedData = gen.generate(processableData, cipher, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	
    	PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl();
    	envelope.setEncoded(envelopedData.getEncoded());
    	envelope.setMessageData(messageData);
    	
		return envelope;
	}
}
