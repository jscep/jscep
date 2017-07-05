package org.jscep.util;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class CertificationRequestUtilsTest {
    private PKCS10CertificationRequest getCsr(ASN1Encodable challengePassword)
            throws Exception {

        final X500Name subject = new X500Name("CN=Test");

        final KeyPair keyPair = KeyPairGenerator.getInstance("RSA")
            .genKeyPair();

        final SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo
            .getInstance(keyPair.getPublic().getEncoded());

        final ContentSigner signer = new JcaContentSignerBuilder(
            "SHA1withRSA").build(keyPair.getPrivate());

        final PKCS10CertificationRequestBuilder builder =
            new PKCS10CertificationRequestBuilder(subject, pkInfo);
        if (challengePassword != null) {
            builder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                challengePassword);
        }
        return builder.build(signer);
    }

    @Test
    public void testGetChallengePasswordPrintableString() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(new DERPrintableString(
            "test password"));
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is("test password"));
    }

    @Test
    public void testGetChallengePasswordUtf8String() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(new DERUTF8String(
            "test_password"));
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is("test_password"));
    }

    @Test
    public void testGetChallengePasswordNull() throws Exception {
        final PKCS10CertificationRequest csr = getCsr(null);
        assertThat(CertificationRequestUtils.getChallengePassword(csr),
                   is(nullValue()));
    }
}
