package com.google.code.jscep.response;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.transaction.CmsException;

public class PkcsPkiEnvelopeTest {
	private PkcsPkiEnvelope fixture;
	
	@BeforeClass
	public static void setUpClass() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Before
	public void setUp() throws Exception {
		final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		final X500Principal subject = new X500Principal("CN=example.org");
		final X509Certificate cert = X509CertificateFactory.createCertificate(subject, keyPair);
		
		CMSSignedDataGenerator sigGen = new CMSSignedDataGenerator();
		final List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(cert);
        final CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
        sigGen.addCertificatesAndCRLs(certs);
        sigGen.addSigner(keyPair.getPrivate(), cert, "1.3.14.3.2.26");
//        CMSSignedData sd = sigGen.generate(null, true, "BC"); 
		
		CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
		envGen.addKeyTransRecipient(cert);
		CMSProcessable bytes = new CMSProcessableByteArray(new byte[0]);
		CMSEnvelopedData ed = envGen.generate(bytes, CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");
		fixture = PkcsPkiEnvelope.getInstance(keyPair, ed.getEncoded());
	}
	
	@Test
	public void testGetCertStore() throws NoSuchProviderException, NoSuchAlgorithmException, CmsException {
		fixture.getCertStore();
	}

}
