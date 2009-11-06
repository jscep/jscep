package com.google.code.jscep.transaction;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Hex;

/**
 * Merge with Enveloper.
 */
public class Signer {
	private final static Logger LOGGER = Logger.getLogger(Signer.class.getName());
	private final String digest;
	private final X509Certificate identity;
	private final KeyPair keyPair;
	
	public Signer(X509Certificate identity, KeyPair keyPair, String digest) {
		this.identity = identity;
		this.keyPair = keyPair;
		this.digest = digest;
	}
	
	public byte[] sign(byte[] data, AttributeTable table) throws IOException, GeneralSecurityException, CmsException {
		CMSProcessable envelopedData = new CMSProcessableByteArray(data);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    	
    	List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(identity);
        
        CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
        try {
			gen.addCertificatesAndCRLs(certs);
		} catch (CMSException e) {
			throw new CmsException(e);
		}
        gen.addSigner(keyPair.getPrivate(), identity, digest, table, null);
        
    	CMSSignedData signedData;
		try {
			signedData = gen.generate(envelopedData, true, "BC");
		} catch (CMSException e) {
			throw new CmsException(e);
		}
    	LOGGER.info("SignedData: " + new String(Hex.encode(signedData.getEncoded())));
    	
    	return signedData.getEncoded();
	}
}
