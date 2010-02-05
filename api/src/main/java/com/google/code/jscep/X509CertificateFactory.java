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
package com.google.code.jscep;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import com.google.code.jscep.util.LoggingUtil;

/**
 * This class is used for generating ephemeral certificates.
 * 
 * @author David Grant
 */
public final class X509CertificateFactory {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep");
	
	private X509CertificateFactory() {
	}

	/**
	 * Creates a self-signed ephemeral certificate.
	 * <p> 
	 * The resulting certificate will have a not-before date
	 * of yesterday, and not-after date of tomorrow.
	 * 
	 * @param subject the subject to certify.
	 * @param keyPair the key pair to sign the certificate with.
	 * @return new certificate.
	 * @throws GeneralSecurityException
	 */
	public static X509Certificate createEphemeralCertificate(X500Principal subject, KeyPair keyPair) throws GeneralSecurityException {
		LOGGER.entering(X509CertificateFactory.class.getName(), "createEphemeralCertificate", new Object[] {subject, keyPair});
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
		gen.setSignatureAlgorithm("SHA1withRSA");
		gen.setSubjectDN(subject);

		X509Certificate cert = gen.generate(keyPair.getPrivate());
		
		LOGGER.exiting(X509CertificateFactory.class.getName(), "createEphemeralCertificate", cert);
		return cert;
	}
	
	public static X509Name toX509Name(X500Principal principal) {
		return new X509Name(principal.getName());
	}
}
