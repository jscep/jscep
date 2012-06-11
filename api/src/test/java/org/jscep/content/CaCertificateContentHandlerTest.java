package org.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;


public class CaCertificateContentHandlerTest {
	private CaCertificateContentHandler fixture;
	
	@Before
	public void setUp() {
		fixture = new CaCertificateContentHandler();
	}
	
	@Test
	public void testSingleCertificate() throws Exception {
		X509Certificate cert = getCertificate();
		
		InputStream in = new ByteArrayInputStream(cert.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-cert");
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
	
	@Test(expected=IOException.class)
	public void testMultipleCertificatesFail() throws Exception {
		X509Certificate cert = getCertificate();
		
		InputStream in = new ByteArrayInputStream(cert.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-ra-cert");
	}

	private X509Certificate getCertificate() throws Exception {
		X500Principal subject = new X500Principal("CN=example.org");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		return X509Util.createEphemeralCertificate(subject, keyPair);
	}
	
	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		InputStream in = new ByteArrayInputStream(new byte[0]);
		fixture.getContent(in, "text/plain");
	}

}
