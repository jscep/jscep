package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> represents the situation where the <tt>Nonce</tt>
 * received in a server response does not match the <tt>Nonce</tt> send in the
 * client request, or where the <tt>Nonce</tt> received has been used before.
 * 
 * @see Nonce
 */
@Immutable
public class InvalidNonceException extends TransactionException {
    private static final String MISMATCH = "Nonce mismatch.  Sent: %s. Receieved: %s";
    private static final String REPLAY = "Nonce encountered before: %s";
    private static final long serialVersionUID = 3875364340108674893L;

    /**
     * Constructs a new <tt>InvalidNonceException</tt> for a <tt>Nonce</tt>
     * mismatch.
     * 
     * @param sent
     *            the sent <tt>Nonce</tt>
     * @param recd
     *            the received <tt>Nonce</tt>
     */
    public InvalidNonceException(Nonce sent, Nonce recd) {
	super(String.format(MISMATCH, sent, recd));
    }

    /**
     * Constructs a new <tt>InvalidNonceException</tt> for a replayed
     * <tt>Nonce</tt>
     * 
     * @param nonce
     *            the replayed <tt>Nonce</tt>.
     */
    public InvalidNonceException(Nonce nonce) {
	super(String.format(REPLAY, nonce));
    }
}
