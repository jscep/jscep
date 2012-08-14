package org.jscep.util;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class X509Certificates {
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
    public static X509Certificate createEphemeral(final X500Principal subject,
	    final KeyPair keyPair) throws GeneralSecurityException {
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
}
