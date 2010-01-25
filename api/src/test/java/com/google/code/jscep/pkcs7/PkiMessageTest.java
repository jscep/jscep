package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.Test;

import com.google.code.jscep.X509CertificateFactory;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.NonceFactory;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

public class PkiMessageTest {
	@Test
	public void testSimple() throws IOException, GeneralSecurityException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X500Principal principal = new X500Principal("CN=example.org");
		X509Certificate identity = X509CertificateFactory.createEphemeralCertificate(principal, keyPair);
		
		PkiMessageGenerator generator = new PkiMessageGenerator();
		generator.setIdentity(identity);
		generator.setTransactionId(TransactionId.createTransactionId());
		generator.setMessageType(MessageType.CertRep);
		generator.setSenderNonce(NonceFactory.nextNonce());
		generator.setKeyPair(keyPair);
		generator.setPkiStatus(PkiStatus.FAILURE);
		generator.setFailInfo(FailInfo.badRequest);
		generator.setRecipientNonce(NonceFactory.nextNonce());
		generator.setDigest(new AlgorithmIdentifier(new DERObjectIdentifier("1.3.14.3.2.26")));		
		PkiMessage genMsg = generator.generate();
		
		PkiMessageParser parser = new PkiMessageParser();
		parser.setPrivateKey(keyPair.getPrivate());
		PkiMessage parsedMsg = parser.parse(genMsg.getEncoded());
		
		System.out.println(genMsg);
		System.out.println(parsedMsg);
	}
}
