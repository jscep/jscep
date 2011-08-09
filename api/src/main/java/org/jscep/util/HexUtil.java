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
package org.jscep.util;

import java.util.Locale;

/**
 * This class provides utilities for converting between byte
 * arrays and hexadecimal strings.
 * 
 * @author David Grant
 */
public final class HexUtil {
	static final byte[] HEX_CHAR_TABLE = {
	    (byte)'0', (byte)'1', (byte)'2', (byte)'3',
	    (byte)'4', (byte)'5', (byte)'6', (byte)'7',
	    (byte)'8', (byte)'9', (byte)'a', (byte)'b',
	    (byte)'c', (byte)'d', (byte)'e', (byte)'f'
	  };
	
	private HexUtil() {
		// This constructor will never be invoked.
	}
	
	/**
	 * Converts the given byte array to an array of hex characters.
	 * 
	 * @param bytes the byte array to convert.
	 * @return an array of hex characters.
	 */
	public static byte[] toHex(byte[] bytes) {
		byte[] hex = new byte[2 * bytes.length];
		int index = 0;
		
		for (byte b : bytes) {
			int v = b & 0xFF;
			hex[index++] = HEX_CHAR_TABLE[v >>> 4];
			hex[index++] = HEX_CHAR_TABLE[v & 0xF];
		}
		
		return hex;
	}
	
	/**
	 * Converts the provided byte array to a string of hex characters.
	 * 
	 * @param bytes the byte array.
	 * @return a string of hex characters.
	 */
	public static String toHexString(byte[] bytes) {
		return new String(toHex(bytes));
	}
	
	/**
	 * Converts the given hex string to a byte array.
	 * 
	 * @param hex the hex string
	 * @return a byte array
	 */
	public static byte[] fromHex(String hex) {
		return fromHex(hex.getBytes());
	}
	
	/**
	 * Converts the given hex array to a byte array
	 * 
	 * @param hex the hex array
	 * @return the byte array
	 */
	public static byte[] fromHex(byte[] hex) {
		byte[] bytes = new byte[hex.length / 2];

		for (int i = 0; i < bytes.length; i++) {
			int v = i * 2;
			int b = Character.digit(hex[v], 16) << 4;
			b = b | Character.digit(hex[v + 1], 16);
			
			bytes[i] = (byte) (b & 0xFF);
		}
		return bytes;
	}

	/**
	 * Converts the given byte array to a formatted hex
	 * string.
	 * 
	 * @param bytes the byte array.
	 * @return the formatted string.
	 */
	public static String format(byte[] bytes) {
		return formatHex(toHex(bytes));
	}

	/**
	 * Converts the given byte array of hex characters 
	 * to a formatted string.

	 * @param hex the byte array.
	 * @return the formatted string.
	 */
	public static String formatHex(byte[] hex) {
		StringBuilder sb = new StringBuilder();
		String s = new String(hex).toUpperCase(Locale.ENGLISH);
		char[] c = s.toCharArray();
		for (int i = 0; i < c.length; i++) {
			if (i % 32 == 0) {
				sb.append("\n\t");
			}
			sb.append(c[i]);
			if (i % 2 != 0) {
				sb.append(" ");
			}
		}
		sb.append("\n");
		return sb.toString();		
	}
}
