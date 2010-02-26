package org.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.SignedData;
import org.jscep.pkcs7.SignedDataGenerator;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;

public class CertRepContentHandlerTest {
	private CertRepContentHandler fixture;
	private KeyPair keyPair;
	private X509Certificate certificate;
	
	@Before
	public void setUp() throws Exception {
		keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		fixture = new CertRepContentHandler(keyPair);
		X500Principal subject = new X500Principal("CN=example.org");
		certificate = X509Util.createEphemeralCertificate(subject, keyPair);
	}

	@Test(expected = IOException.class)
	public void testGetBadContent() throws Exception {
		SignedDataGenerator gen = new SignedDataGenerator();
		gen.addSigner(keyPair.getPrivate(), certificate, "MD5", null, null);
		SignedData signedData = gen.generate();
		
		InputStream in = new ByteArrayInputStream(signedData.getEncoded());
		fixture.getContent(in, "application/x-pki-message");
	}

	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		InputStream in = new ByteArrayInputStream(new byte[0]);
		fixture.getContent(in, "text/plain");
	}
}
