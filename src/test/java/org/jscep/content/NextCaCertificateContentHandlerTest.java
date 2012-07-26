package org.jscep.content;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.transport.response.InvalidContentTypeException;
import org.jscep.util.X509Certificates;
import org.junit.Before;
import org.junit.Test;

public class NextCaCertificateContentHandlerTest {
    private GetNextCaCertResponseHandler fixture;

    @Before
    public void setUp() throws Exception {
        KeyPair keyPair = getKeyPair();
        X509Certificate ca = getCertificate(keyPair);
        fixture = new GetNextCaCertResponseHandler(ca);
    }

    // @Test
    // public void testSuccess() throws Exception {
    // // We need a DSD wrapped in a SD. This is only a DSD.
    // final SignedDataGenerator generator = new SignedDataGenerator();
    // generator.addSigner(keyPair.getPrivate(), ca, "SHA-1", null, null);
    // generator.addCertificate(ca);
    // final SignedData degenerateSignedData = generator.generate();
    // final SignedData signedData =
    // generator.generate(PKCSObjectIdentifiers.signedData,
    // degenerateSignedData);
    //
    // final InputStream in = new
    // ByteArrayInputStream(MessageData.getInstance(signedData).getEncoded());
    // final List<X509Certificate> certs = fixture.getContent(in,
    // "application/x-x509-next-ca-cert");
    //
    // Assert.assertEquals(1, certs.size());
    // Assert.assertTrue(certs.contains(ca));
    // }

    // @Test(expected = IOException.class)
    // public void testInvalidSigner() throws Exception {
    // final KeyPair invalidKeyPair = getKeyPair();
    // final X509Certificate invalidCertificate =
    // getCertificate(invalidKeyPair);
    //
    // // We need a DSD wrapped in a SD. This is only a DSD.
    // final SignedDataGenerator generator = new SignedDataGenerator();
    // generator.addSigner(invalidKeyPair.getPrivate(), invalidCertificate,
    // "SHA-1", null, null);
    // generator.addCertificate(invalidCertificate);
    // final SignedData degenerateSignedData = generator.generate();
    // final SignedData signedData =
    // generator.generate(PKCSObjectIdentifiers.signedData,
    // degenerateSignedData);
    //
    // final InputStream in = new
    // ByteArrayInputStream(MessageData.getInstance(signedData).getEncoded());
    // fixture.getContent(in, "application/x-x509-next-ca-cert");
    // }

    // @Test(expected=IOException.class)
    // public void testInvalidMime() throws Exception {
    // final SignedDataGenerator generator = new SignedDataGenerator();
    // generator.addSigner(keyPair.getPrivate(), ca, "SHA-1", null, null);
    // generator.addCertificate(ca);
    // SignedData dsd = generator.generate();
    //
    // InputStream in = new ByteArrayInputStream(dsd.getEncoded());
    // fixture.getContent(in, "foo/bar");
    // }

    @Test(expected = InvalidContentTypeException.class)
    public void testInvalidContent() throws Throwable {
        fixture.getResponse(new byte[] {1}, "application/x-x509-next-ca-cert");
    }

    private X509Certificate getCertificate(KeyPair keyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=example.org");
        return X509Certificates.createEphemeral(subject, keyPair);
    }

    private KeyPair getKeyPair() throws Exception {
        return KeyPairGenerator.getInstance("RSA").genKeyPair();
    }
}
