package com.google.code.jscep.transaction;

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

}
