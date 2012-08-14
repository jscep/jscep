package org.jscep.client;

public class ClientException extends Exception {
    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public ClientException(Throwable cause) {
	super(cause);
    }

    public ClientException(String message) {
	super(message);
    }
}
