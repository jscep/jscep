package org.jscep.message;

public class MessageEncodingException extends Exception {
    /**
     * 
     */
    private static final long serialVersionUID = -6111956271602335933L;

    public MessageEncodingException(Throwable cause) {
        super(cause);
    }

    public MessageEncodingException(String message) {
        super(message);
    }
}
