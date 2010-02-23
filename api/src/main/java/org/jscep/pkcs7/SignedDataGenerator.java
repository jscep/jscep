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
package org.jscep.pkcs7;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.util.AlgorithmDictionary;
import org.jscep.util.LoggingUtil;


/**
 * This class is used for generating degenerate (certificates and CRLs only) 
 * {@link org.bouncycastle.asn1.cms.SignedData} instances.
 * <p>
 * Example usage:
 * <pre>
 * X509Certificate cert = ...;
 * 
 * SignedDataGenerator gen = new SignedDataGenerator();
 * gen.addCertificate(cert);
 * SignedData signedData = gen.generate();
 * </pre>
 * 
 * @author David Grant
 */
public class SignedDataGenerator {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private final List<X509Certificate> certs;
	private final List<X509CRL> crls;
	private final String digestAlgorithm = "MD5";
	
	/**
	 * Creates a new instance of <code>SignedDataGenerator</code>
	 */
	public SignedDataGenerator() {
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
	 * Generates a new {@link org.bouncycastle.asn1.cms.SignedData} instance.
	 * 
	 * @return a new <code>SignedData</code> instance.
	 * @throws IOException if any I/O error occurs.
	 * @throws NoSuchAlgorithmException 
	 */
	public SignedData generate() throws IOException {
		LOGGER.entering(getClass().getName(), "generate");
		
		final DERSet digestAlgorithms = getDigestAlgorithmIdentifiers();
		final ContentInfo contentInfo = getContentInfo();
		DERSet signerInfos;
		try {
			signerInfos = getSignerInfos();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		final DERSet certificates = getCertificates();
		final DERSet crls = getCRLs();
		
		final SignedData sd = new SignedData(digestAlgorithms, contentInfo, certificates, crls, signerInfos);
		
		LOGGER.exiting(getClass().getName(), "generate", sd);
		return sd;
	}
	
	private ContentInfo getContentInfo() {
		return new ContentInfo(getContentType(), getContent());
	}
	
	private DEREncodable getContent() {
		return new DEROctetString(new byte[0]);
	}
	
	private DERObjectIdentifier getContentType() {
		return CMSObjectIdentifiers.data;
	}
	
	private DERSet getDigestAlgorithmIdentifiers() {
		return new DERSet();
	}
	
	private DERSet getSignerInfos() throws NoSuchAlgorithmException {
		return new DERSet(getSignerInfoVector());
	}
	
	private DEREncodableVector getSignerInfoVector() throws NoSuchAlgorithmException {
		final DEREncodableVector v = new ASN1EncodableVector();
		
		for (X509Certificate signer : certs) {
			final SignerIdentifier signerIdentifier = getSignerIdentifier(signer);
			final AlgorithmIdentifier digestAlgorithm = getDigestAlgorithm();
			final DERSet authenticatedAttributes = getAuthenticatedAttributes();
			final AlgorithmIdentifier digestEncryptionAlgorithm = getDigestEncryptionAlgorithm(signer);
			final ASN1OctetString encryptedDigest = getEncryptedDigest();
			final DERSet unauthenticatedAttributes = getUnauthenticatedAttributes();
			
			SignerInfo signerInfo = new SignerInfo(signerIdentifier, 
												   digestAlgorithm,
												   authenticatedAttributes,
												   digestEncryptionAlgorithm,
												   encryptedDigest,
												   unauthenticatedAttributes);
			v.add(signerInfo);
		}
		
		return v;
	}
	
	private DERSet getCertificates() throws IOException {
		return new DERSet(getCertificatesVector());
	}
	
	private DEREncodableVector getCertificatesVector() throws IOException {
		final DEREncodableVector v = new ASN1EncodableVector();
		
		for (Certificate cert : certs) {
			try {
				v.add(ASN1Object.fromByteArray(cert.getEncoded()));
			} catch (CertificateEncodingException e) {
				// This is thrown if an encoding error occurs.
				throw new IOException(e);
			}
		}
		
		return v;
	}
	
	private DERSet getCRLs() throws IOException {
		return new DERSet(getCRLsVector());
	}
	
	private DEREncodableVector getCRLsVector() throws IOException {
		final DEREncodableVector v = new ASN1EncodableVector();
		
		for (CRL crl : crls) {
			final X509CRL x509crl = (X509CRL) crl;
			try {
				v.add(ASN1Object.fromByteArray(x509crl.getEncoded()));
			} catch (CRLException e) {
				// This is thrown if an encoding error occurs.
				throw new IOException(e);
			}
		}
		
		return v;
	}
	
	private SignerIdentifier getSignerIdentifier(X509Certificate signer) {
		return new SignerIdentifier(getIssuerAndSerialNumber(signer));
	}
	
	private IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate certificate) {
		return new IssuerAndSerialNumber(getIssuerName(certificate), certificate.getSerialNumber());
	}
	
	private X509Name getIssuerName(X509Certificate certificate) {
		return new X509Name(certificate.getIssuerDN().getName());
	}
	
	private AlgorithmIdentifier getDigestAlgorithm() {
		return AlgorithmDictionary.getAlgId(digestAlgorithm);
	}
	
	private DERSet getAuthenticatedAttributes() {
		// TODO
		return new DERSet();
	}
	
	private AlgorithmIdentifier getDigestEncryptionAlgorithm(X509Certificate certificate) {
		// I would expect this to always be RSA.
		return AlgorithmDictionary.getAlgId(certificate.getPublicKey().getAlgorithm());
	}
	
	private byte[] getMessageDigest() throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
		
		return digest.digest();
	}
	
	private ASN1OctetString getEncryptedDigest() throws NoSuchAlgorithmException {
		byte[] digest = getMessageDigest();
		// TODO
		return new DEROctetString(new byte[0]);
	}
	
	private DERSet getUnauthenticatedAttributes() {
		// TODO
		return new DERSet();
	}
}
