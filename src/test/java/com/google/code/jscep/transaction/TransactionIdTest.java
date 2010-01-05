package com.google.code.jscep.transaction;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.Assert;
import org.junit.Test;

public class TransactionIdTest {

	@Test
	public void testCreateTransactionIdKeyPairString() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = generator.generateKeyPair();
		
		TransactionId transA = TransactionId.createTransactionId(keyPair);
		TransactionId transB = TransactionId.createTransactionId(keyPair);
		
		Assert.assertEquals(transA, transB);
	}

	@Test
	public void testCreateTransactionId() {
		TransactionId transA = TransactionId.createTransactionId();
		TransactionId transB = TransactionId.createTransactionId();
		
		Assert.assertFalse(transA.equals(transB));
	}

	@Test
	public void testCreateTransactionIdNullKeyPair() {
		TransactionId transA = TransactionId.createTransactionId(null);
		TransactionId transB = TransactionId.createTransactionId(null);
		
		Assert.assertFalse(transA.equals(transB));
	}
	
	@Test
	public void testTransactionIdByteArray() {
		final byte[] bytes = new byte[0];
		
		TransactionId transA = new TransactionId(bytes);
		TransactionId transB = new TransactionId(bytes);
		
		Assert.assertEquals(transA, transB);
	}
}
