package org.jscep.message;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.util.X509Certificates;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PkiMessageEncoderTest {
    @Parameters
    public static Collection<Object[]> getParameters() throws Exception {
	List<Object[]> params = new ArrayList<Object[]>();

	KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	TransactionId transId = TransactionId.createTransactionId();
	Nonce recipientNonce = Nonce.nextNonce();
	Nonce senderNonce = recipientNonce;
	X500Name issuer = new X500Name("CN=CA");
	X500Name subject = new X500Name("CN=Client");
	IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
	BigInteger serial = BigInteger.ONE;
	IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);
	PKCS10CertificationRequest csr = getCsr(new X500Principal("CN=Client"),
		pair.getPublic(), pair.getPrivate(), "password".toCharArray());
	CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
		.build(pair.getPrivate());
	X509Certificate cert = X509Certificates.createEphemeral(
		new X500Principal("CN=client"), pair);
	Store certs = new JcaCertStore(Collections.singleton(cert));
	gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
		new JcaDigestCalculatorProviderBuilder().build()).build(
		sha1Signer, cert));
	gen.addCertificates(certs);
	CMSTypedData msg = new CMSAbsentContent();
	CMSSignedData sigData = gen.generate(msg, false);

	params.add(new Object[] { new GetCert(transId, senderNonce, iasn) });
	params.add(new Object[] { new GetCertInitial(transId, senderNonce, ias) });
	params.add(new Object[] { new GetCrl(transId, senderNonce, iasn) });
	params.add(new Object[] { new PkcsReq(transId, senderNonce, csr) });
	params.add(new Object[] { new CertRep(transId, senderNonce,
		recipientNonce) });
	params.add(new Object[] { new CertRep(transId, senderNonce,
		recipientNonce, sigData) });
	params.add(new Object[] { new CertRep(transId, senderNonce,
		recipientNonce, FailInfo.badAlg) });

	return params;
    }

    private final PkiMessage<?> message;

    public PkiMessageEncoderTest(PkiMessage<?> message) {
	this.message = message;
    }

    @Test
    public void simpleTest() throws Exception {
	KeyPair caPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
	X509Certificate ca = X509Certificates.createEphemeral(
		new X500Principal("CN=CA"), caPair);

	KeyPair clientPair = KeyPairGenerator.getInstance("RSA")
		.generateKeyPair();
	X509Certificate client = X509Certificates.createEphemeral(
		new X500Principal("CN=Client"), clientPair);

	// Everything below this line only available to client
	PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(ca);
	PkiMessageEncoder encoder = new PkiMessageEncoder(
		clientPair.getPrivate(), client, envEncoder);

	PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(ca,
		caPair.getPrivate());
	PkiMessageDecoder decoder = new PkiMessageDecoder(client, envDecoder);

	PkiMessage<?> actual = decoder.decode(encoder.encode(message));

	assertEquals(message, actual);
    }

    private static PKCS10CertificationRequest getCsr(X500Principal subject,
	    PublicKey pubKey, PrivateKey priKey, char[] password)
	    throws GeneralSecurityException, IOException {
	DERPrintableString cpSet = new DERPrintableString(new String(password));
	SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pubKey
		.getEncoded());

	JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
		"SHA1withRSA");
	ContentSigner signer;
	try {
	    signer = signerBuilder.build(priKey);
	} catch (OperatorCreationException e) {
	    IOException ioe = new IOException();
	    ioe.initCause(e);

	    throw ioe;
	}

	PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
		X500Name.getInstance(subject.getEncoded()), pkInfo);
	builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
		cpSet);

	return builder.build(signer);
    }
}
