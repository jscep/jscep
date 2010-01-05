package com.google.code.jscep.request;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import com.google.code.jscep.pkcs7.PkcsPkiEnvelope;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.NonceFactory;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.TransactionId;

public class PkiRequestTest {
	private PkiMessage message;
	private PkiRequest fixture;
	
	@Before
	public void setUp() throws Exception {
		message = new MockPkiMessage();
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
		
		fixture = new PkiRequest(message, keyPair);
	}
	
	@Test
	public void testGetMessage() throws IOException {
		Assert.assertEquals(message.getEncoded(), fixture.getMessage());
	}

	@Test
	public void testGetOperation() {
		Assert.assertEquals(Operation.PKIOperation, fixture.getOperation());
	}
	
	@Test
	public void testContentHandler() {
		Assert.assertNotNull(fixture.getContentHandler());
	}

	private static class MockPkiMessage implements PkiMessage {
		private byte[] bytes = new byte[0];
		
		public byte[] getEncoded() {
			return bytes;
		}

		public FailInfo getFailInfo() {
			return null;
		}

		public PkcsPkiEnvelope getPkcsPkiEnvelope() {
			return null;
		}

		public Nonce getRecipientNonce() {
			return NonceFactory.nextNonce();
		}

		public Nonce getSenderNonce() {
			return NonceFactory.nextNonce();
		}

		public PkiStatus getStatus() {
			return PkiStatus.SUCCESS;
		}

		public TransactionId getTransactionId() {
			return TransactionId.createTransactionId();
		}
		
	}
}
