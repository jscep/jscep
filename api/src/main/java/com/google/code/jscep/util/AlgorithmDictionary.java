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
package com.google.code.jscep.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERObjectIdentifier;
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
 */
public final class AlgorithmDictionary {
	// 1.2.840.113549.2.5 -> md5
	// 1.3.14.3.2.26 -> sha
	// 2.16.840.1.101.3.4.2.1 -> sha256
	// 2.16.840.1.101.3.4.2.3 -> sha512
	
	// 1.2.840.113549.1.1.1 -> rsa
	
	// 1.3.14.3.2.7 -> des
	// 1.2.840.113549.3.7 -> desede
	
	// 1.2.840.113549.1.1.4 -> md5withRSA
	// 1.2.840.113549.1.1.5 -> shaWithRSA
	// 1.2.840.113549.1.1.11 -> sha256withRSA
	// 1.2.840.113549.1.1.13 -> sha512withRSA
	private final static Map<DERObjectIdentifier, String> contents = new HashMap<DERObjectIdentifier, String>();
	static {
		contents.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		contents.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1withRSA");
		contents.put(SMIMECapabilities.dES_CBC, "DES/CBC/PKCS5Padding");
		contents.put(SMIMECapabilities.dES_EDE3_CBC, "3DES/CBC/PKCS5Padding");
		contents.put(X509ObjectIdentifiers.id_SHA1, "SHA");
	}
	
	/**
	 * Private constructor to prevent instantiation.
	 */
	private AlgorithmDictionary() {}
	
	/**
	 * Returns the name of the provided OID.
	 * 
	 * @param oid the Object Identifier.
	 * @return the algorithm name.
	 */
	public static String lookup(DERObjectIdentifier oid) {
		return contents.get(oid);
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
}
