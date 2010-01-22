package com.google.code.jscep.transaction;

/**
 * This class represents the error condition when an invalid
 * Nonce is received by a SCEP peer.
 */
public class InvalidNonceException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3875364340108674893L;
	
	/**
	 * Constructs a new InvalidNonceException with the specified detail message.
	 * 
	 * @param msg the detail message.
	 */
	public InvalidNonceException(String msg) {
		super(msg);
	}

}
