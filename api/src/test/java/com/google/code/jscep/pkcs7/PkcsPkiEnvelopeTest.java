package com.google.code.jscep.pkcs7;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.transaction.CmsException;

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
		final X509Certificate cert = X509CertificateFactory.createCertificate(subject, keyPair);

		final PkcsPkiEnvelopeGenerator envGenerator = new PkcsPkiEnvelopeGenerator();
		envGenerator.setCipher(getCipherAlgorithm());
		envGenerator.setRecipient(cert);
		
		fixture = envGenerator.generate(msgData);
	}
	
	private static AlgorithmIdentifier getCipherAlgorithm() {
		// DES
		return new AlgorithmIdentifier(new DERObjectIdentifier("1.3.14.3.2.7"));
	}
	
	@Test
	public void testGetCertStore() throws NoSuchProviderException, NoSuchAlgorithmException, CmsException {
		Assert.assertEquals(msgData, fixture.getMessageData());
	}

}
