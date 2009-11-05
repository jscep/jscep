package com.google.code.jscep.transaction;

import java.security.SecureRandom;
import java.util.Random;

public final class NonceFactory {
	private static final Random RND = new SecureRandom();
	
	private NonceFactory() {
	}
	
	public static Nonce nextNonce() {
		byte[] bytes = new byte[16];
		RND.nextBytes(bytes);
		
		return new Nonce(bytes);
	}
}
