package org.jscep.x509;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * This is a utility class for performing various operations pertaining to X.500
 * objects.
 */
public final class X509Util {
    // TODO: Consider moving this to the org.jscep.util package.
    // TODO: Consider renaming this class too. There are no certificate
    // operations.
    private X509Util() {
	// This constructor will never be invoked.
    }

    /**
     * Converts a Java SE X500Principal to a Bouncy Castle X500Name.
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
     * Extracts the <tt>PublicKey</tt> from the provided CSR.
     * <p>
     * This method will throw a {@link RuntimeException} if the JRE is missing
     * the RSA algorithm, which is a required algorithm as defined by the JCA.
     * 
     * @param csr
     *            the CSR to extract from.
     * @return the extracted <tt>PublicKey</tt>
     * @throws InvalidKeySpecException
     *             if the CSR is not using an RSA key.
     * @throws IOException
     *             if there is an error extracting the <tt>PublicKey</tt>
     *             parameters.
     */
    public static PublicKey getPublicKey(PKCS10CertificationRequest csr)
	    throws InvalidKeySpecException, IOException {
	SubjectPublicKeyInfo pubKeyInfo = csr.getSubjectPublicKeyInfo();
	RSAKeyParameters keyParams = (RSAKeyParameters) PublicKeyFactory
		.createKey(pubKeyInfo);
	KeySpec keySpec = new RSAPublicKeySpec(keyParams.getModulus(),
		keyParams.getExponent());

	KeyFactory kf;
	try {
	    kf = KeyFactory.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException(e);
	}
	return kf.generatePublic(keySpec);
    }
}
