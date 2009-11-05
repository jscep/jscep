package com.google.code.jscep.transaction;

import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Logger;

public final class NonceFactory {
	private final static Logger LOGGER = Logger.getLogger(NonceFactory.class.getName());
	private static final Random RND = new SecureRandom();
	
	private NonceFactory() {
	}
	
	public static Nonce nextNonce() {
		LOGGER.info("Generating New Nonce");
		
		byte[] bytes = new byte[16];
		RND.nextBytes(bytes);
		
		return new Nonce(bytes);
	}
}
