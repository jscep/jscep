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
package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import com.google.code.jscep.util.LoggingUtil;

/**
 * This class is used for generating degenerate (certificates and CRLs only) 
 * {@link org.bouncycastle.asn1.cms.SignedData} instances.
 * <p>
 * Example usage:
 * <pre>
 * X509Certificate cert = ...;
 * 
 * DegenerateSignedDataGenerator gen = new DegenerateSignedDataGenerator();
 * gen.addCertificate(cert);
 * SignedData signedData = gen.generate();
 * </pre>
 * 
 * @author David Grant
 */
public class DegenerateSignedDataGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private final List<X509Certificate> certs;
	private final List<X509CRL> crls;
	
	/**
	 * Creates a new instance of <code>DegenerateSignedDataGenerator</code>
	 */
	public DegenerateSignedDataGenerator() {
		certs = new LinkedList<X509Certificate>();
		crls = new LinkedList<X509CRL>();
	}
	
	/**
	 * Adds the provided certificate to the resulting {@link org.bouncycastle.asn1.cms.SignedData}.
	 * 
	 * @param cert the certificate to add.
	 */
	public void addCertificate(X509Certificate cert) {
		certs.add(cert);
	}
	
	/**
	 * Adds the provided CRL to the resulting {@link org.bouncycastle.asn1.cms.SignedData}.
	 * 
	 * @param crl the CRL to add.
	 */
	public void addCRL(X509CRL crl) {
		crls.add(crl);
	}
	
	/**
	 * Generates a new degenerate {@link org.bouncycastle.asn1.cms.SignedData} instance.
	 * 
	 * @return a new degenerate <code>SignedData</code> instance.
	 * @throws IOException if any I/O error occurs.
	 */
	public SignedData generate() throws IOException {
		LOGGER.entering(getClass().getName(), "generate");
		
		final DERSet digestAlgorithms = new DERSet();
		ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(new byte[0]));
		final DERSet signerInfos = new DERSet();
		final DEREncodableVector certVector = new ASN1EncodableVector();
		final DEREncodableVector crlVector = new ASN1EncodableVector();
		try {
			for (Certificate cert : certs) {
				certVector.add(ASN1Object.fromByteArray(cert.getEncoded()));
			}
			for (CRL crl : crls) {
				X509CRL x509crl = (X509CRL) crl;
				crlVector.add(ASN1Object.fromByteArray(x509crl.getEncoded()));
			}
		} catch (GeneralSecurityException e) {
			
			LOGGER.throwing(getClass().getName(), "generate", e);
			throw new RuntimeException(e);
		}
		final DERSet certs = new DERSet(certVector);
		final DERSet crls = new DERSet(crlVector);
		
		final SignedData sd = new SignedData(digestAlgorithms, contentInfo, certs, crls, signerInfos);
		
		LOGGER.exiting(getClass().getName(), "generate", sd);
		return sd;
	}
}
