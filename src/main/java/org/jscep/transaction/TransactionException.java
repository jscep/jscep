package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> represents any failure occurring in the transaction
 * layer.
 */
@Immutable
public class TransactionException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new <tt>TransactionException</tt> caused by the provided
     * <tt>Throwable</tt>.
     * 
     * @param cause
     *            the <tt>Throwable</tt> that caused the error.
     */
    public TransactionException(Throwable cause) {
	super(cause);
    }

    /**
     * Creates a new <tt>TransactionException</tt> with the provided error
     * message.
     * 
     * @param message
     *            a description of the error condition.
     */
    public TransactionException(String message) {
	super(message);
    }
}
