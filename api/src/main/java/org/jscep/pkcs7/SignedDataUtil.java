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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.util.AlgorithmDictionary;
import org.jscep.x509.X509Util;


/**
 * This class contains utility methods for manipulating SignedData
 * objects.
 * 
 * @author David Grant
 */
public final class SignedDataUtil {
	/**
	 * Private constructor to prevent instantiation.
	 */
	private SignedDataUtil() {}
	/**
	 * Extracts a CertStore from the provided PKCS #7 SignedData object.
	 * 
	 * @param signedData the PKCS #7 SignedData object.
	 * @return the CertStore.
	 * @throws GeneralSecurityException if any security error is encountered.
	 */
	public static CertStore extractCertStore(SignedData signedData) throws GeneralSecurityException {
		final CertificateFactory factory = CertificateFactory.getInstance("X.509");
		final Collection<Object> collection = new HashSet<Object>();
		final ASN1Set certs = signedData.getCertificates();
		final ASN1Set crls = signedData.getCRLs();
		
		if (certs != null) {
			final Enumeration<?> certEnum = certs.getObjects();
			while (certEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) certEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				Certificate cert = factory.generateCertificate(bais);
				collection.add(cert);
			}
		}
		if (crls != null) {
			final Enumeration<?> crlEnum = crls.getObjects();
			while (crlEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) crlEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				CRL crl = factory.generateCRL(bais);
				collection.add(crl);
			}
		}
		
		final CertStoreParameters parameters = new CollectionCertStoreParameters(collection);
		return CertStore.getInstance("Collection", parameters);
	}
	
	/**
	 * Checks if the provided signedData was signed by the entity represented
	 * by the provided certificate.
	 *  
	 * @param signedData the signedData to verify.
	 * @param signer the signing entity.
	 * @return <code>true</code> if the signedData was signed by the entity, <code>false</code> otherwise.
	 */
	public static boolean isSignedBy(SignedData signedData, X509Certificate signer) {
		X509Name signerName = X509Util.toX509Name(signer.getIssuerX500Principal());
		BigInteger signerSerialNo = signer.getSerialNumber();
		IssuerAndSerialNumber issuerIasn = new IssuerAndSerialNumber(signerName, signerSerialNo);
		
		final ASN1Set signerInfos = signedData.getSignerInfos();
		@SuppressWarnings("unchecked")
		Enumeration<ASN1Sequence> seqs = signerInfos.getObjects();
		while (seqs.hasMoreElements()) {
			final ASN1Sequence seq = seqs.nextElement();
			SignerInfo signerInfo = new SignerInfo(seq);
			signerInfo.getAuthenticatedAttributes();
			SignerIdentifier signerId = signerInfo.getSID();
			IssuerAndSerialNumber iasn = IssuerAndSerialNumber.getInstance(signerId.getId());
			
			if (issuerIasn.equals(iasn) == false) {
				continue;
			}
			// We've found the right issuer.
			ASN1OctetString signedDigest = signerInfo.getEncryptedDigest();
			String hashAlg = AlgorithmDictionary.lookup(signerInfo.getDigestAlgorithm());
			String sigAlg = AlgorithmDictionary.getRSASignatureAlgorithm(hashAlg);
			Signature sig;
			try {
				sig = Signature.getInstance(sigAlg);
			} catch (NoSuchAlgorithmException e) {
				return false;
			}
			try {
				sig.initVerify(signer);
			} catch (InvalidKeyException e) {
				return false;
			}
			try {
				sig.update(getHash(signerInfo));
				return sig.verify(signedDigest.getOctets());
			} catch (SignatureException e) {
				return false;
			} catch (IOException e) {
				return false;
			}
		}
		
		return false;
	}
	
	private static byte[] getHash(SignerInfo signerInfo) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final DEROutputStream dos = new DEROutputStream(baos);
		dos.writeObject(signerInfo.getAuthenticatedAttributes());
		dos.close();

		return baos.toByteArray();
	}
}
