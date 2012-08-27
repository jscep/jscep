package org.jscep.message;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> is thrown whenever jscep is unable to decode a SCEP
 * secure message object.
 */
@Immutable
public class MessageDecodingException extends Exception {
    private static final long serialVersionUID = -6111956271602335933L;

    /**
     * Creates a new <tt>MessageDecodingException</tt> with the provided cause.
     * 
     * @param cause
     *            the initial cause of the decoding exception.
     */
    public MessageDecodingException(Throwable cause) {
	super(cause);
    }

    /**
     * Creates a new <tt>MessageDecodingException</tt> with the provided error
     * message.
     * 
     * @param message
     *            the description of the decoding exception.
     */
    public MessageDecodingException(String message) {
	super(message);
    }
}
