package com.google.code.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.pkcs7.DegenerateSignedDataGenerator;
import com.google.code.jscep.pkcs7.MessageData;

public class CaCertificateContentHandlerTest {
	private CaCertificateContentHandler fixture;
	
	@BeforeClass
	public static void setUpClass() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
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
	
	@Test(expected=IOException.class)
	public void testSingleCertificateFail() throws Exception {
		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.addCertificate(getCertificate());
		SignedData dsd = generator.generate();
		
		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-cert");
	}
	
	@Test(expected=IOException.class)
	public void testMultipleCertificatesFail() throws Exception {
		X509Certificate cert = getCertificate();
		
		InputStream in = new ByteArrayInputStream(cert.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-ra-cert");
	}
	
	@Test
	public void testMultipleCertificates() throws Exception {
		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.addCertificate(getCertificate());
		SignedData sd = generator.generate();
		MessageData md = MessageData.getInstance(sd);
		
		InputStream in = new ByteArrayInputStream(md.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-ra-cert");
	}
	
	private X509Certificate getCertificate() throws Exception {
		X500Principal subject = new X500Principal("CN=example.org");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		X509Certificate cert = X509CertificateFactory.createEphemeralCertificate(subject, keyPair);
		
		return cert;
	}
	
	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		InputStream in = new ByteArrayInputStream(new byte[0]);
		fixture.getContent(in, "text/plain");
	}

}
