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

import static com.google.common.base.Charsets.US_ASCII;

import java.io.UnsupportedEncodingException;


/**
 * This class provides utilities for converting between byte
 * arrays and hexadecimal strings.
 *
 * @author David Grant
 */
public final class HexUtil {
    static final byte[] HEX_CHAR_TABLE = {
            (byte) '0', (byte) '1', (byte) '2', (byte) '3',
            (byte) '4', (byte) '5', (byte) '6', (byte) '7',
            (byte) '8', (byte) '9', (byte) 'a', (byte) 'b',
            (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'
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
        try {
			return new String(toHex(bytes), US_ASCII.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
    }

    /**
     * Converts the given hex string to a byte array.
     *
     * @param hex the hex string
     * @return a byte array
     */
    public static byte[] fromHex(String hex) {
        try {
			return fromHex(hex.getBytes(US_ASCII.name()));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
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
}
