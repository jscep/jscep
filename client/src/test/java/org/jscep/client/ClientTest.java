package org.jscep.client;

import static org.hamcrest.core.Is.is;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

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
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.x509.X509Util;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

public class ClientTest extends AbstractClientTest {
	/**
	 * The requester MUST use RSA keys for all symmetric key operations.
	 * 
	 * @throws Exception if any error occurs.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testRsa() throws Exception {
		final KeyPair keyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
		final X509Certificate identity = X509Util.createEphemeralCertificate(new X500Principal("CN=jscep.org"), keyPair);
		final URL url = new URL("http://jscep.org/pkiclient.exe");
		
		new Client(url, identity, keyPair.getPrivate(), new NoSecurityCallbackHandler());
	}
	
	@Test
	public void testRenewalEnrollAllowed() throws Exception {
		// Ignore this test if the CA doesn't support renewal.
		Assume.assumeTrue(client.getCaCapabilities().isRenewalSupported());
		
		CertificationRequest csr = getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password);
		Transaction t = client.enrollCertificate(csr);
		if (t.getState() == State.CERT_ISSUED) {
			t.getCertStore();
		}
	}

	/**
	 * CAs that do advertise support for renewal should not perform it!
	 * 
	 * @throws Exception
	 */
	@Test(expected = IOException.class)
	public void testRenewalSameCAEnrollDisallowed() throws Exception {
		// Ignore if renewal is supported.
		Assume.assumeThat(client.getCaCapabilities().isRenewalSupported(), is(false));

		Transaction trans;
		State state;
		CertificationRequest csr = getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password);
		
		trans = client.enrollCertificate(csr);
		state = trans.getState();
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
		
		trans = client.enrollCertificate(csr);
		state = trans.getState();
		if (state == State.CERT_ISSUED) {
			identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		}
	}

	@Test
	public void testEnroll() throws Exception {
		CertificationRequest csr = getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password);
		Transaction trans = client.enrollCertificate(csr);
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			CertStore store = trans.getCertStore();
			System.out.println(store.getCertificates(null));
		}
	}
	
	@Test
	public void testEnrollThenGet() throws Exception {		
		Transaction trans = client.enrollCertificate(getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), password));
		State state = trans.getState();
		Assume.assumeTrue(state == State.CERT_ISSUED);
		identity = (X509Certificate) trans.getCertStore().getCertificates(null).iterator().next();
		Certificate retrieved = client.getCertificate(identity.getSerialNumber()).iterator().next();
		
		Assert.assertEquals(identity, retrieved);
	}
	
	@Test(expected = IOException.class)
	public void testEnrollInvalidPassword() throws Exception {
		Transaction trans = client.enrollCertificate(getCsr(identity.getSubjectX500Principal(), keyPair.getPublic(), keyPair.getPrivate(), new char[0]));
		State state = trans.getState();
		if (state == State.CERT_ISSUED) {
			trans.getCertStore();
		}
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
