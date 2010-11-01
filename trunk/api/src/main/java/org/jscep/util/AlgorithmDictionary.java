/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.util;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * This class provides a utility to lookup a friendly name for an algorithm given
 * a particular OID or AlgorithmIdentifier.
 * <p>
 * The internal dictionary is by no means comprehensive, and new algorithms are
 * generally as and when they are required by changes to the SCEP specification.
 * 
 * @author David Grant
 * @link http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html
 */
public final class AlgorithmDictionary {
	private static Logger LOGGER = LoggingUtil.getLogger(AlgorithmDictionary.class);
	/**
	 * JCA standards RECOMMEND NoPadding and PKCS5Padding to Providers.
	 * 
	 * PKCS5Padding is more secure than NoPadding, so we use that.
	 */
	private static final String PADDING = "PKCS5Padding";
	/**
	 * JCA standards RECOMMEND CBC and ECB to Providers.
	 * 
	 * CBC is more secure than EBC, so we use that.
	 */
	private static final String MODE = "CBC";
	private final static Map<DERObjectIdentifier, String> contents = new HashMap<DERObjectIdentifier, String>();
	static {
		// Asymmetric Ciphers
		contents.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		// Digital Signatures
		contents.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1withRSA");
		contents.put(new DERObjectIdentifier("1.2.840.113549.1.1.4"), "md5withRSA");
		contents.put(new DERObjectIdentifier("1.2.840.113549.1.1.11"), "sha256withRSA");
		contents.put(new DERObjectIdentifier("1.2.840.113549.1.1.13"), "sha512withRSA");
		// Symmetric Ciphers
		contents.put(SMIMECapabilities.dES_CBC, "DES/CBC/PKCS5Padding"); // DES
		contents.put(SMIMECapabilities.dES_EDE3_CBC, "3DES/CBC/PKCS5Padding"); // DESEDE
		// Message Digests
		contents.put(X509ObjectIdentifiers.id_SHA1, "SHA");
		contents.put(new DERObjectIdentifier("1.2.840.113549.2.5"), "MD5");
		contents.put(new DERObjectIdentifier("2.16.840.1.101.3.4.2.1"), "SHA-256");
		contents.put(new DERObjectIdentifier("2.16.840.1.101.3.4.2.3"), "SHA-512");
	}
	
	
	private final static Map<String, DERObjectIdentifier> oids = new HashMap<String, DERObjectIdentifier>();
	static {
		// Cipher
		oids.put("DES/CBC/PKCS5Padding", OIWObjectIdentifiers.desCBC);
		oids.put("DESede/CBC/PKCS5Padding", PKCSObjectIdentifiers.des_EDE3_CBC);
		// KeyFactory or KeyPairGenerator
		oids.put("RSA", PKCSObjectIdentifiers.rsaEncryption);
		// KeyGenerator, AlgorithmParameters or SecretKeyFactory
		oids.put("DES", null);
		oids.put("DESede", null);
		// MessageDigest
		oids.put("MD5", PKCSObjectIdentifiers.md5);
		oids.put("SHA-1", X509ObjectIdentifiers.id_SHA1);
		oids.put("SHA-256", NISTObjectIdentifiers.id_sha256);
		oids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
		// Signature
		oids.put("MD5withRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
		oids.put("SHA1withRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
		oids.put("SHA256withRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
		oids.put("SHA512withRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
	}
	
	private AlgorithmDictionary() {
		// This constructor will never be invoked.
	}
	
	/**
	 * Returns the OID for the provided algorithm name.
	 * 
	 * @param algorithm the algorithm name, e.g. "RSA"
	 * @return the corresponding OID, or null.
	 */
	public static DERObjectIdentifier getOid(String algorithm) {
		LOGGER.entering(AlgorithmDictionary.class.getName(), "getOid", new Object[] {algorithm});
		
		final DERObjectIdentifier oid = oids.get(algorithm);
		
		LOGGER.exiting(AlgorithmDictionary.class.getName(), "getOid");
		
		return oid;
	}
	
	/**
	 * Returns an AlgorithmIdentifier to represent the provider algorithm.
	 * @param algorithm the algorithm name, e.g. "RSA"
	 * @return the corresponding algorithm identifier, or null;
	 */
	public static AlgorithmIdentifier getAlgId(String algorithm) {
		DERObjectIdentifier oid = getOid(algorithm);
		if (oid == null) {
			return null;
		} else {
			return new AlgorithmIdentifier(oid);
		}
	}
	
	/**
	 * Returns an appropriate transformation name for the given cipher.
	 * <p>
	 * In the JCA, an instance of a {@link Cipher} may be obtained using just
	 * the cipher algorithm (e.g. DES), but this is subject to defaults
	 * specified by the provider, so we "fill out" the cipher name in this method, so
	 * that <code>DES</code> becomes <code>DES/CBC/PKC5Padding</code> 
	 * 
	 * @param cipher the cipher algorithm name.
	 * @return the transformation name
	 * @throws IllegalArgumentException if the cipher algorithm is not appropriate.
	 */
	public static String getTransformation(String cipher) throws IllegalArgumentException {
		if (cipher.equalsIgnoreCase("DES") || cipher.equalsIgnoreCase("DESede")) {
			return cipher + "/" + MODE + "/" + PADDING;
		} else {
			throw new IllegalArgumentException(cipher + " is not an appropriate cipher name");
		}
	}
	
	/**
	 * Returns the cipher part of the provided transformation.
	 * 
	 * @param transformation the transformation, e.g. "DES/CBC/PKCS5Padding"
	 * @return the cipher, e.g. "DES"
	 */
	public static String fromTransformation(String transformation) {
		return transformation.split("/")[0];
	}
	
	/**
	 * Returns the name of the given algorithm.
	 * 
	 * @param alg the algorithm to look up.
	 * @return the algorithm name.
	 */
	public static String lookup(AlgorithmIdentifier alg) {
		return contents.get(alg.getObjectId());
	}
	
	/**
	 * Returns the signature algorithm name for a given hash algorithm to be used
	 * with a RSA cipher.
	 * <p>
	 * For example, "SHA-1" becomes "SHA1withRSA".
	 *  
	 * @param hashAlgorithm the hash algorithm to use. 
	 * @return the signature algorithm name.
	 */
	public static String getRSASignatureAlgorithm(String hashAlgorithm) {
		if (hashAlgorithm.equals("SHA")) {
			return "SHA1withRSA";
		} else if (hashAlgorithm.startsWith("SHA-")) {
			return hashAlgorithm.replace("-", "") + "withRSA";
		} else {
			return hashAlgorithm + "withRSA";
		}
	}
}
