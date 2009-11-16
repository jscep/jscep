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

package com.google.code.jscep.util;

public final class HexUtil {
	static final byte[] HEX_CHAR_TABLE = {
	    (byte)'0', (byte)'1', (byte)'2', (byte)'3',
	    (byte)'4', (byte)'5', (byte)'6', (byte)'7',
	    (byte)'8', (byte)'9', (byte)'A', (byte)'B',
	    (byte)'C', (byte)'D', (byte)'E', (byte)'F'
	  };   
	
	private HexUtil() {		
	}
	
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
	
	public static String format(byte[] bytes) {
		return formatHex(toHex(bytes));
	}

	public static String formatHex(byte[] hex) {
		StringBuilder sb = new StringBuilder();
		String s = new String(hex).toUpperCase();
		char[] c = s.toCharArray();
		for (int i = 0; i < c.length; i++) {
			if (i % 32 == 0) {
				sb.append("\n\t");
			}
			sb.append(c[i]);
			if (i % 2 == 1) {
				sb.append(" ");
			}
		}
		sb.append("\n");
		return sb.toString();		
	}
}
