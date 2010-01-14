package com.google.code.jscep.transaction;

import org.junit.Assert;
import org.junit.Test;

public class NonceFactoryTest {

	@Test
	public void testNextNonce() {
		Nonce nonce1 = NonceFactory.nextNonce();
		Nonce nonce2 = NonceFactory.nextNonce();
		
		Assert.assertFalse(nonce1.equals(nonce2));
	}

}
