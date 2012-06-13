package org.jscep.content;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;


public class CaCertificateContentHandlerTest {
    private CaCertificateContentHandler fixture;

    @Before
    public void setUp() throws Exception {
    	CertificateFactory factory = CertificateFactory.getInstance("X509");
        fixture = new CaCertificateContentHandler(factory);
    }

    @Test
    public void testSingleCertificate() throws Exception {
        X509Certificate cert = getCertificate();

        fixture.getContent(cert.getEncoded(), "application/x-x509-ca-cert");
    }

//	@Test(expected=IOException.class)
//	public void testSingleCertificateFail() throws Exception {
//		final SignedDataGenerator generator = new SignedDataGenerator();
//		generator.addCertificate(getCertificate());
//		SignedData dsd = generator.generate();
//		
//		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
//		fixture.getContent(in, "application/x-x509-ca-cert");
//	}

    @Test(expected = InvalidContentException.class)
    public void testMultipleCertificatesFail() throws Exception {
        X509Certificate cert = getCertificate();

        fixture.getContent(cert.getEncoded(), "application/x-x509-ca-ra-cert");
    }

    private X509Certificate getCertificate() throws Exception {
        X500Principal subject = new X500Principal("CN=example.org");
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
        return X509Util.createEphemeralCertificate(subject, keyPair);
    }

    @Test(expected = InvalidContentTypeException.class)
    public void testInvalidMime() throws Exception {
        fixture.getContent(new byte[0], "text/plain");
    }

}
