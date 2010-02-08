package com.google.code.jscep.pkcs7;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.jscep.x509.X509Util;

public class PkcsPkiEnvelopeTest {
	private ASN1Encodable msgData;
	private PkcsPkiEnvelope fixture;
	
	@BeforeClass
	public static void setUpClass() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Before
	public void setUp() throws Exception {
		msgData = new DERUTF8String("Sample");
		
		final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		final X500Principal subject = new X500Principal("CN=example.org");
		final X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);

		final PkcsPkiEnvelopeGenerator envGenerator = new PkcsPkiEnvelopeGenerator();
		envGenerator.setCipherAlgorithm("DES");
		envGenerator.setRecipient(cert);
		envGenerator.setMessageData(MessageData.getInstance(msgData));
		envGenerator.setKeyAlgorithm("DES");
		
		fixture = envGenerator.generate();
	}
	
	@Test
	public void testGetCertStore() throws NoSuchProviderException, NoSuchAlgorithmException {
		Assert.assertEquals(msgData, fixture.getMessageData().getContent());
	}

}
