package com.google.code.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Before;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.pkcs7.DegenerateSignedData;
import com.google.code.jscep.pkcs7.DegenerateSignedDataGenerator;

public class NextCaCertificateContentHandlerTest {
	private NextCaCertificateContentHandler fixture;
	private X509Certificate ca;
	
	@Before
	public void setUp() throws Exception {
		ca = getCertificate();
		fixture = new NextCaCertificateContentHandler(ca);
	}
	
	@Test
	public void testSuccess() throws Exception {
		CertStore store = getCertStore();

		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.setCertStore(store);
		DegenerateSignedData dsd = generator.generate();
		
		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
		fixture.getContent(in, "application/x-x509-next-ca-cert");
	}
	
	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		CertStore store = getCertStore();

		final DegenerateSignedDataGenerator generator = new DegenerateSignedDataGenerator();
		generator.setCertStore(store);
		DegenerateSignedData dsd = generator.generate();
		
		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
		fixture.getContent(in, "foo/bar");
	}
	
	@Test(expected=IOException.class)
	public void testInvalidContent() throws Throwable {
		InputStream in = new ByteArrayInputStream(new byte[] {1});
		
		fixture.getContent(in, "application/x-x509-next-ca-cert");
	}
	
	private X509Certificate getCertificate() throws Exception {
		X500Principal subject = new X500Principal("CN=example.org");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		X509Certificate cert = X509CertificateFactory.createCertificate(subject, keyPair);
		
		return cert;
	}

	private CertStore getCertStore() throws Exception {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		certs.add(ca);
		
		CollectionCertStoreParameters params = new CollectionCertStoreParameters(certs);
		CertStore store = CertStore.getInstance("Collection", params);
		
		return store;
	}
}
