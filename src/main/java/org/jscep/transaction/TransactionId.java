package org.jscep.transaction;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;

/**
 * This class represents a SCEP <code>transactionID</code> attribute.
 */
public final class TransactionId implements Serializable {
	private static final long serialVersionUID = -5248125945726721520L;
	private static final AtomicLong ID_SOURCE = new AtomicLong();
	private final byte[] id;

	/**
	 * Creates a new <tt>TransactionId</tt> from the provided byte array.
	 * 
	 * @param id
	 *            the ID to copy.
	 */
	public TransactionId(byte[] id) {
		this.id = ArrayUtils.clone(id);
	}

	private TransactionId(PublicKey pubKey, String digestAlgorithm) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		id = new Hex().encode(digest.digest(pubKey.getEncoded()));
	}

	private TransactionId() {
		try {
			id = Long.toHexString(ID_SOURCE.getAndIncrement()).getBytes(
					Charsets.US_ASCII.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Creates a new Transaction ID
	 * <p>
	 * Each call to this method will return the same transaction ID given the
	 * same parameters.
	 * 
	 * @param pubKey
	 *            the key on which to base the transaction ID.
	 * @param digestAlgorithm
	 *            the algorithm to use to digest the key
	 * @return the new <tt>TransactionID</tt>
	 */
	public static TransactionId createTransactionId(PublicKey pubKey,
			String digestAlgorithm) {
		return new TransactionId(pubKey, digestAlgorithm);
	}

	/**
	 * Creates a new Transaction Id
	 * <p>
	 * Each call to this method will return a different transaction ID.
	 * 
	 * @return the new <tt>TransactionID</tt>
	 */
	public static TransactionId createTransactionId() {
		return new TransactionId();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		try {
			return new String(id, Charsets.US_ASCII.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
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

		TransactionId that = (TransactionId) o;

		return Arrays.equals(id, that.id);

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Arrays.hashCode(id);

	}
}
