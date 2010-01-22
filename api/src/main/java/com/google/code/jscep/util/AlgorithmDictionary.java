package com.google.code.jscep.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public final class AlgorithmDictionary {
	private final static Map<DERObjectIdentifier, String> contents = new HashMap<DERObjectIdentifier, String>();
	static {
		contents.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		contents.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1withRSA");
		contents.put(SMIMECapabilities.dES_CBC, "DES/CBC/PKCS5Padding");
		contents.put(SMIMECapabilities.dES_EDE3_CBC, "3DES/CBC/PKCS5Padding");
		contents.put(X509ObjectIdentifiers.id_SHA1, "SHA");
	}
	
	public static String lookup(DERObjectIdentifier oid) {
		return contents.get(oid);
	}
	
	public static String lookup(AlgorithmIdentifier alg) {
		return contents.get(alg.getObjectId());
	}
}
