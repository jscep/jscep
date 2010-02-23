package com.google.code.jscep.transaction;

import org.jscep.transaction.Nonce;
import org.junit.Assert;
import org.junit.Test;

public class NonceTest {

	@Test
	public void testGetBytes() {
		final byte[] bytes = new byte[0];
		final Nonce nonce = new Nonce(bytes);
		
		Assert.assertSame(bytes, nonce.getBytes());
	}

	@Test
	public void testEquals() {
		Assert.assertEquals(new Nonce(new byte[0]), new Nonce(new byte[0]));
	}
	
	@Test
	public void testNextNonce() {
		Nonce nonce1 = Nonce.nextNonce();
		Nonce nonce2 = Nonce.nextNonce();
		
		Assert.assertFalse(nonce1.equals(nonce2));
	}
}
