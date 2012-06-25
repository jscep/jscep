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

import static com.google.common.base.Charsets.US_ASCII;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.jscep.util.HexUtil;

import com.google.common.primitives.Bytes;


/**
 * This class represents the SCEP <code>transactionID</code> attribute.
 *
 * @author David Grant
 */
public final class TransactionId {
    private static final AtomicLong ID_SOURCE = new AtomicLong();
    private final byte[] id;

    public TransactionId(byte[] id) {
        this.id = Bytes.concat(id);
    }

    private TransactionId(PublicKey pubKey, String digestAlgorithm) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        id = HexUtil.toHex(digest.digest(pubKey.getEncoded()));
    }

    private TransactionId() {
        try {
			id = Long.toHexString(ID_SOURCE.getAndIncrement()).getBytes(US_ASCII.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
    }

    public byte[] getBytes() {
        return Bytes.concat(id);
    }


    /**
     * Creates a new Transaction Id
     * <p/>
     * Each call to this method will return the same transaction ID for the same parameters.
     *
     * @param pubKey          public key
     * @param digestAlgorithm digest algorithm
     * @return the new Transaction Id
     */
    public static TransactionId createTransactionId(PublicKey pubKey, String digestAlgorithm) {
        return new TransactionId(pubKey, digestAlgorithm);
    }

    /**
     * Creates a new Transaction Id
     * <p/>
     * Each call to this method will return a different transaction ID.
     *
     * @return the new Transaction Id
     */
    public static TransactionId createTransactionId() {
        return new TransactionId();
    }

    @Override
    public String toString() {
        try {
			return new String(id, US_ASCII.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TransactionId that = (TransactionId) o;

        return Arrays.equals(id, that.id);

    }

    @Override
    public int hashCode() {
   		return Arrays.hashCode(id);

    }
}
