package org.jscep.transport;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.bouncycastle.asn1.DERNull;
import org.eclipse.jetty.server.Server;
import org.jscep.pkcs7.MessageData;
import org.jscep.pkcs7.PkiMessage;
import org.jscep.pkcs7.PkiMessageGenerator;
import org.jscep.request.PKCSReq;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.Transport.Method;
import org.jscep.x509.X509Util;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

abstract public class AbstractTransportTest {
	protected URL url;
	protected Proxy proxy;
	protected Transport transport;
	private Server server;
	
	@Before
	public void setUp() throws Exception {
		server = new Server(0);
		server.start();
		url = new URL("http://localhost:" + server.getConnectors()[0].getLocalPort() + "/");
		proxy = Proxy.NO_PROXY;
		transport = Transport.createTransport(getMethod(), url, proxy);
	}
	
	abstract protected Method getMethod();
	
	@After
	public void tearDown() throws Exception {
		server.stop();
	}
	
	@Test
	public void testGetURL() {
		Assert.assertEquals(url, transport.getURL());
	}

	@Test
	public void testGetProxy() {
		Assert.assertEquals(proxy, transport.getProxy());
	}

	@Test
	public void test404() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
//		SignedDataGenerator gen = new SignedDataGenerator();
//		SignedData signedData = gen.generate();
		PkiMessageGenerator msgGenerator = new PkiMessageGenerator();
		msgGenerator.setTransactionId(TransactionId.createTransactionId());
		msgGenerator.setMessageType(MessageType.GetCert);
		msgGenerator.setSenderNonce(Nonce.nextNonce());
		msgGenerator.setMessageDigest("MD5");
		msgGenerator.setCipherAlgorithm("DES");
		msgGenerator.setKeyPair(keyPair);
		msgGenerator.setSigner(getCertificate(keyPair));
		msgGenerator.setRecipient(getCertificate(keyPair));
		msgGenerator.setMessageData(MessageData.getInstance(new DERNull()));
		PkiMessage msgData = msgGenerator.generate();
		PKCSReq req = new PKCSReq(msgData, keyPair);
		
		try {
			transport.sendMessage(req);
		} catch (IOException e) {
			Assert.assertEquals(e.getMessage(), "404 Not Found");
		}
	}
	
	private X509Certificate getCertificate(KeyPair keyPair) throws GeneralSecurityException {
		final X500Principal subject = new X500Principal("CN=example.org");
		
		return X509Util.createEphemeralCertificate(subject, keyPair);
	}
}
