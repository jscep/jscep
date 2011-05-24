/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.jscep.util.LoggingUtil;


/**
 * This is a utility class for performing various operations pertaining to X.509
 * certificates.
 * 
 * @author David Grant
 */
public final class X509Util {
	private static Logger LOGGER = LoggingUtil.getLogger(X509Util.class);
	
	private X509Util() {
		// This constructor will never be invoked.
	}

	/**
	 * Creates a self-signed ephemeral certificate.
	 * <p> 
	 * The resulting certificate will have a not-before date
	 * of yesterday, and not-after date of tomorrow.
	 * 
	 * @param subject the subject to certify.
	 * @param keyPair the key pair to sign the certificate with.
	 * @return a new certificate.
	 * @throws GeneralSecurityException if any security problem occurs.
	 */
	public static X509Certificate createEphemeralCertificate(X500Principal subject, KeyPair keyPair) throws GeneralSecurityException {
		LOGGER.entering(X509Util.class.getName(), "createEphemeralCertificate", new Object[] {subject, keyPair});
		final Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DATE, -1);
		final Date notBefore = cal.getTime();
		cal.add(Calendar.DATE, 2);
		final Date notAfter = cal.getTime();
		
		final X509V1CertificateGenerator gen = new X509V1CertificateGenerator();
		gen.setIssuerDN(subject);
		gen.setNotBefore(notBefore);
		gen.setNotAfter(notAfter);
		gen.setPublicKey(keyPair.getPublic());
		gen.setSerialNumber(BigInteger.ONE);
		gen.setSignatureAlgorithm("SHA1with" + keyPair.getPublic().getAlgorithm());
		gen.setSubjectDN(subject);

		X509Certificate cert = gen.generate(keyPair.getPrivate());
		
		LOGGER.exiting(X509Util.class.getName(), "createEphemeralCertificate", cert);
		return cert;
	}
	
	/**
	 * Converts a Java SE X500Principal to a Bouncy Castle X509Name.
	 * 
	 * @param principal the principal to convert.
	 * @return the converted name.
	 */
	public static X509Name toX509Name(X500Principal principal) {
		try {
			byte[] bytes = principal.getEncoded();
			return new X509Name((ASN1Sequence) ASN1Object.fromByteArray(bytes));
		} catch (IOException e) {
			return null;
		}
	}
	
	/**
	 * Checks the provided certificate to see if it is self-signed.
	 * 
	 * @param cert the certificate to check.
	 * @return <code>true</code> if the certificate is self-signed, <code>false</code> otherwise.
	 */
	public static boolean isSelfSigned(X509Certificate cert) {
		try {
    		cert.verify(cert.getPublicKey());
    		
    		return true;
    	} catch (Exception e) {
    		return false;
    	}
	}

	/**
	 * Creates a new IssuerAndSerialNumber from the provided certificate.
	 * 
	 * @param certificate the certificate to use.
	 * @return the IssuerAndSerialNumber to represent the certificate.
	 */
	public static IssuerAndSerialNumber toIssuerAndSerialNumber(X509Certificate certificate) {
		final X509Name issuer = X509Util.toX509Name(certificate.getIssuerX500Principal());
		return new IssuerAndSerialNumber(issuer, certificate.getSerialNumber());
	}
	
	public static PublicKey getPublicKey(CertificationRequest csr) throws IOException {
		SubjectPublicKeyInfo pubKeyInfo = csr.getCertificationRequestInfo().getSubjectPublicKeyInfo();
    	RSAKeyParameters keyParams = (RSAKeyParameters) PublicKeyFactory.createKey(pubKeyInfo);
    	KeySpec keySpec = new RSAPublicKeySpec(keyParams.getModulus(), keyParams.getExponent());

		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(keySpec);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
