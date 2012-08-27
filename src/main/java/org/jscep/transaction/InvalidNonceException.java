package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> represents the situation where the nonce received in a server response does not match
 * the nonce send in the client request.
 * 
 * @see Nonce
 */
@Immutable
public class InvalidNonceException extends TransactionException {
    private static final long serialVersionUID = 3875364340108674893L;

    /**
     * Constructs a new <tt>InvalidNonceException</tt> with the specified detail message.
     * 
     * @param msg
     *            the detail message.
     */
    public InvalidNonceException(String msg) {
	// TODO: Construct this exception with the sender and recipient nonces.
	super(msg);
    }

}
