package com.google.code.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.pkcs7.DegenerateSignedData;
import com.google.code.jscep.pkcs7.DegenerateSignedDataGenerator;

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
		CertStore store = getCertStore();

		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.setCertStore(store);
		DegenerateSignedData dsd = generator.generate();
		
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
		CertStore store = getCertStore();

		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.setCertStore(store);
		DegenerateSignedData dsd = generator.generate();
		
		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
		fixture.getContent(in, "application/x-x509-ca-ra-cert");
	}
	
	private X509Certificate getCertificate() throws Exception {
		X500Principal subject = new X500Principal("CN=example.org");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		X509Certificate cert = X509CertificateFactory.createEphemeralCertificate(subject, keyPair);
		
		return cert;
	}

	private CertStore getCertStore() throws Exception {
		X509Certificate cert = getCertificate();
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		certs.add(cert);
		
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(certs);
		CertStore store = CertStore.getInstance("Collection", params);
		
		return store;
	}
	
	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		InputStream in = new ByteArrayInputStream(new byte[0]);
		fixture.getContent(in, "text/plain");
	}

}
