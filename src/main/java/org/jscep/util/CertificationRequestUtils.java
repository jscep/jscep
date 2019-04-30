package org.jscep.util;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * This class is used for performing utility operations on
 * <tt>CertificationRequest</tt> instances.
 */
public final class CertificationRequestUtils {
    private CertificationRequestUtils() {
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
     * @throws IOException
     *             if there is an error extracting the <tt>PublicKey</tt>
     *             parameters.
     */
    public static PublicKey getPublicKey(final PKCS10CertificationRequest csr)
            throws IOException {
		SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(pkInfo);
    }

    /**
     * Extracts the <tt>Challenge password</tt> from the provided CSR.
     * <p>
     * 
     * @param csr
     *            the CSR to extract from.
     * @return the extracted <tt>Challenge password</tt>
     */
    public static String getChallengePassword(final PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes();
        for (Attribute attr : attrs) {
            if (attr.getAttrType().equals(
                    PKCSObjectIdentifiers.pkcs_9_at_challengePassword)) {
                // According to RFC 2985 this may be any of the DirectoryString
                // types, but we can be more flexible and allow any ASN.1
                // string.
                ASN1String challengePassword = (ASN1String) attr
                        .getAttrValues().getObjectAt(0);
                return challengePassword.getString();
            }
        }
        return null;
    }


}
