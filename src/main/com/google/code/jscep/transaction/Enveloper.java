package com.google.code.jscep.transaction;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.util.encoders.Hex;

/**
 * Merge with Signer.
 */
public class Enveloper {
	private final static Logger LOGGER = Logger.getLogger(Enveloper.class.getName());
	private final String cipher;
	private final X509Certificate ca;
	
	public Enveloper(X509Certificate ca, String cipher) {
		this.ca = ca;
		this.cipher = cipher;
	}
	
	public byte[] envelope(byte[] messageData) throws IOException, GeneralSecurityException, CmsException {
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    	gen.addKeyTransRecipient(ca);
    	CMSProcessable processableData = new CMSProcessableByteArray(messageData);
    	CMSEnvelopedData envelopedData;
		try {
			envelopedData = gen.generate(processableData, cipher, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	LOGGER.info("EnvelopedData: " + new String(Hex.encode(envelopedData.getEncoded())));
    	return envelopedData.getEncoded();
	}
}
