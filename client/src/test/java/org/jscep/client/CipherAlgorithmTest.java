package org.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.jscep.response.Capability;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class CipherAlgorithmTest extends AbstractClientTest {
	@Test
	public void testCipherDES() throws Exception {
		testCipher("DES");
	}
	
	@Test
	public void testCipher3DES() throws Exception {
		Assume.assumeTrue(client.getCaCapabilities().contains(Capability.TRIPLE_DES));
		
		testCipher("DESede");
	}
	
	@Ignore @Test(expected = IOException.class)
	public void testCipher3DESUnsupported() throws Exception {
		Assume.assumeThat(client.getCaCapabilities().contains(Capability.TRIPLE_DES), is(false));
		
		testCipher("DESede");
	}
	
	private void testCipher(String cipher) throws Exception {
		client.setPreferredCipherAlgorithm(cipher);
		client.enrol(getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password));
	}
	
	private CertificationRequest getCsr(X500Principal subject, PublicKey pubKey, PrivateKey priKey, char[] password) throws GeneralSecurityException, IOException {
		AlgorithmIdentifier sha1withRsa = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		
		ASN1Set cpSet = new DERSet(new DERPrintableString(new String(password)));
		Attribute challengePassword = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, cpSet);
		ASN1Set attrs = new DERSet(challengePassword);

		SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Object.fromByteArray(pubKey.getEncoded()));
		
		X509Name name = new X509Name(subject.toString());
		CertificationRequestInfo requestInfo = new CertificationRequestInfo(name, pkInfo, attrs);
		
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(priKey);
		signer.update(requestInfo.getEncoded());
		byte[] signatureBytes = signer.sign();
		DERBitString signature = new DERBitString(signatureBytes);
		
		return new CertificationRequest(requestInfo, sha1withRsa, signature);
	}
}
