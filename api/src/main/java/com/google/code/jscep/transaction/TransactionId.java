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

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import com.google.code.jscep.util.HexUtil;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents the <tt>SCEP</tt> <tt>transactionID</tt> attribute.
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-3.1.1.1">SCEP Internet-Draft Reference</a>
 */
public final class TransactionId {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transaction");
	private static final AtomicLong ID_SOURCE = new AtomicLong();
	private final byte[] id;
	
	public TransactionId(byte[] id) {
		this.id = id;
	}
	
	private TransactionId(KeyPair keyPair, String digestAlgorithm) {
    	MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        id = HexUtil.toHex(digest.digest(keyPair.getPublic().getEncoded()));
	}
	
	private TransactionId() {
		id = Long.toHexString(ID_SOURCE.getAndIncrement()).getBytes();
	}
	
	public byte[] getBytes() {
		return id;
	}
	
	@Override
	public boolean equals(Object o) {
		TransactionId transId = (TransactionId) o;
		
		return Arrays.equals(transId.getBytes(), getBytes());
	}
	
	/**
	 * Creates a new Transaction Id
	 * <p>
	 * Each call to this method will return the same transaction ID for the same parameters.
	 * 
	 * @return the new Transaction Id
	 */
	public static TransactionId createTransactionId(KeyPair keyPair, String digestAlgorithm) {
		LOGGER.entering(TransactionId.class.getName(), "createTransactionId", new Object[] {keyPair, digestAlgorithm});
		
		TransactionId t = new TransactionId(keyPair, digestAlgorithm);

		LOGGER.exiting(TransactionId.class.getName(), "createTransactionId", t);
		return t;
	}
	
	/**
	 * Creates a new Transaction Id
	 * <p>
	 * Each call to this method will return a different transaction ID.
	 * 
	 * @return the new Transaction Id
	 */
	public static TransactionId createTransactionId() {
		LOGGER.entering(TransactionId.class.getName(), "createTransactionId");
		
		TransactionId t =  new TransactionId();
		
		LOGGER.exiting(TransactionId.class.getName(), "createTransactionId", t);
		return t;
	}
	
	@Override
	public String toString() {
		return new String(id);
	}
}
