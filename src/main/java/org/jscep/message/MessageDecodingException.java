package org.jscep.message;

import net.jcip.annotations.Immutable;

@Immutable
public class MessageDecodingException extends Exception {
    private static final long serialVersionUID = -6111956271602335933L;

    public MessageDecodingException(Throwable cause) {
	super(cause);
    }

    public MessageDecodingException(String message) {
	super(message);
    }
}
