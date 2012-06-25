/*
 * Copyright (c) 2009-2010 David Grant
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
package org.jscep.transaction;

import org.jscep.util.HexUtil;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * This class represents the <code>senderNonce</code> and
 * <code>recipientNonce</code> types.
 * 
 * @author David Grant
 */
public class Nonce {
	private static final Random RND = new SecureRandom();
	private byte[] nonce;

	/**
	 * Creates a new nonce with the given byte array.
	 * 
	 * @param nonce
	 *            the byte array.
	 */
	public Nonce(byte[] nonce) {
		this.nonce = copy(nonce);
	}

	/**
	 * Returns the nonce byte array.
	 * 
	 * @return the byte array.
	 */
	public byte[] getBytes() {
		return copy(nonce);
	}

	@Override
	public String toString() {
		return "Nonce [" + HexUtil.toHexString(nonce) + "]";
	}

	/**
	 * Generates a new random Nonce.
	 * <p/>
	 * This method does not guarantee that multiple invocations will produce a
	 * different nonce, as the byte generation is provided by a SecureRandom
	 * instance.
	 * 
	 * @return the generated nonce.
	 * @see java.security.SecureRandom
	 */
	public static Nonce nextNonce() {
		byte[] bytes = new byte[16];
		RND.nextBytes(bytes);

		return new Nonce(bytes);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		Nonce nonce1 = (Nonce) o;

		return Arrays.equals(nonce, nonce1.nonce);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(nonce);
	}

	private static byte[] copy(byte[] source) {
		byte[] dest = new byte[source.length];
		System.arraycopy(source, 0, dest, 0, source.length);

		return dest;
	}
}
