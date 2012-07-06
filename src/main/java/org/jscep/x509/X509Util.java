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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * This is a utility class for performing various operations pertaining to X.509
 * certificates.
 * 
 * @author David Grant
 */
public final class X509Util {
    private X509Util() {
        // This constructor will never be invoked.
    }

    /**
     * Creates a self-signed ephemeral certificate.
     * <p/>
     * The resulting certificate will have a not-before date of yesterday, and
     * not-after date of tomorrow.
     * 
     * @param subject
     *            the subject to certify.
     * @param keyPair
     *            the key pair to sign the certificate with.
     * @return a new certificate.
     * @throws GeneralSecurityException
     *             if any security problem occurs.
     */
    public static X509Certificate createEphemeralCertificate(
            final X500Principal subject, final KeyPair keyPair)
            throws GeneralSecurityException {
        final Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, -1);
        final Date notBefore = cal.getTime();
        cal.add(Calendar.DATE, 2);
        final Date notAfter = cal.getTime();

        
        
        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder(sigAlg(keyPair)).build(keyPair
                    .getPrivate());
        } catch (OperatorCreationException e) {
            throw new GeneralSecurityException(e);
        }
        JcaX509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject,
                keyPair.getPublic());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String sigAlg(KeyPair keyPair) {
        return "SHA1with" + keyPair.getPrivate().getAlgorithm();
    }

    /**
     * Converts a Java SE X500Principal to a Bouncy Castle X509Name.
     * 
     * @param principal
     *            the principal to convert.
     * @return the converted name.
     */
    public static X500Name toX509Name(X500Principal principal) {
        byte[] bytes = principal.getEncoded();
        return X500Name.getInstance(bytes);
    }

    /**
     * Checks the provided certificate to see if it is self-signed.
     * 
     * @param cert
     *            the certificate to check.
     * @return <code>true</code> if the certificate is self-signed,
     *         <code>false</code> otherwise.
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());

            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Creates a new IssuerAndSerialNumber from the provided certificate.
     * 
     * @param certificate
     *            the certificate to use.
     * @return the IssuerAndSerialNumber to represent the certificate.
     */
    public static IssuerAndSerialNumber toIssuerAndSerialNumber(
            X509Certificate certificate) {
        final X500Name issuer = X509Util.toX509Name(certificate
                .getIssuerX500Principal());
        return new IssuerAndSerialNumber(issuer, certificate.getSerialNumber());
    }

    public static PublicKey getPublicKey(PKCS10CertificationRequest csr)
            throws IOException {
        SubjectPublicKeyInfo pubKeyInfo = csr.getSubjectPublicKeyInfo();
        RSAKeyParameters keyParams = (RSAKeyParameters) PublicKeyFactory
                .createKey(pubKeyInfo);
        KeySpec keySpec = new RSAPublicKeySpec(keyParams.getModulus(),
                keyParams.getExponent());

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(keySpec);
        } catch (Exception e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
    }
}
