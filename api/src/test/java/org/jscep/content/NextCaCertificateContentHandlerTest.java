package org.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.jscep.pkcs7.MessageData;
import org.jscep.pkcs7.SignedDataGenerator;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;


public class NextCaCertificateContentHandlerTest {
	private NextCaCertificateContentHandler fixture;
	private X509Certificate ca;
	private KeyPair keyPair;
	
	@Before
	public void setUp() throws Exception {
		keyPair = getKeyPair();
		ca = getCertificate(keyPair);
		fixture = new NextCaCertificateContentHandler(ca);
	}
	
	@Ignore @Test
	public void testSuccess() throws Exception {
		// We need a DSD wrapped in a SD.  This is only a DSD.
		final SignedDataGenerator generator = new SignedDataGenerator();
		generator.addSigner(keyPair.getPrivate(), ca, "SHA-1", null, null);
		generator.addCertificate(ca);
		SignedData dsd = generator.generate();
		SignedData sd = generator.generate(PKCSObjectIdentifiers.signedData, dsd);
		
		InputStream in = new ByteArrayInputStream(MessageData.getInstance(sd).getEncoded());
		fixture.getContent(in, "application/x-x509-next-ca-cert");
	}
	
	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		final SignedDataGenerator generator = new SignedDataGenerator();
		generator.addSigner(keyPair.getPrivate(), ca, "SHA-1", null, null);
		generator.addCertificate(ca);
		SignedData dsd = generator.generate();
		
		InputStream in = new ByteArrayInputStream(dsd.getEncoded());
		fixture.getContent(in, "foo/bar");
	}
	
	@Test(expected=IOException.class)
	public void testInvalidContent() throws Throwable {
		InputStream in = new ByteArrayInputStream(new byte[] {1});
		
		fixture.getContent(in, "application/x-x509-next-ca-cert");
	}
	
	private X509Certificate getCertificate(KeyPair keyPair) throws Exception {
		X500Principal subject = new X500Principal("CN=example.org");
		X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);
		
		return cert;
	}
	
	private KeyPair getKeyPair() throws Exception {
		return KeyPairGenerator.getInstance("RSA").genKeyPair();
	}
}
