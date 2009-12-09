/*
 * Copyright (c) 2009 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.google.code.jscep.transaction;

import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Logger;

import com.google.code.jscep.util.HexUtil;

/**
 * This class is used for generating nonces.
 */
public final class NonceFactory {
	private final static Logger LOGGER = Logger.getLogger(NonceFactory.class.getName());
	private static final Random RND = new SecureRandom();
	
	/**
	 * Prevent instantiation.
	 */
	private NonceFactory() {
	}
	
	/**
	 * Generates a new random Nonce.
	 * <p>
	 * This method does not guarantee that multiple invocations will produce a different
	 * nonce, as the byte generation is provided by a SecureRandom instance.
	 * 
	 * @return the generated nonce.
	 * @see java.security.SecureRandom
	 */
	public static Nonce nextNonce() {
		LOGGER.info("Generating New Nonce");
		
		byte[] bytes = new byte[16];
		RND.nextBytes(bytes);
		
		LOGGER.info("Nonce:\n" + HexUtil.format(bytes));
		
		return new Nonce(bytes);
	}
}
