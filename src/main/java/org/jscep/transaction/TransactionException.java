package org.jscep.transaction;

public class TransactionException extends Exception {
    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public TransactionException(Throwable cause) {
        super(cause);
    }

    public TransactionException(String message) {
        super(message);
    }
}
