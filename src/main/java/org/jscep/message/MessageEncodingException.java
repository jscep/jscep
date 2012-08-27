package org.jscep.message;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> is thrown whenever jscep is unable to encode a SCEP
 * secure message object.
 */
@Immutable
public class MessageEncodingException extends Exception {
    private static final long serialVersionUID = -6111956271602335933L;

    /**
     * Creates a new <tt>MessageEncodingException</tt> with the provided cause.
     * 
     * @param cause
     *            the initial cause of the encoding exception.
     */
    public MessageEncodingException(Throwable cause) {
	super(cause);
    }

    /**
     * Creates a new <tt>MessageEncodingException</tt> with the provided error
     * message.
     * 
     * @param message
     *            the description of the encoding exception.
     */
    public MessageEncodingException(String message) {
	super(message);
    }
}
