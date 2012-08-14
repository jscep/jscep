package org.jscep.message;

import net.jcip.annotations.Immutable;

@Immutable
public class MessageEncodingException extends Exception {
    private static final long serialVersionUID = -6111956271602335933L;

    public MessageEncodingException(Throwable cause) {
	super(cause);
    }

    public MessageEncodingException(String message) {
	super(message);
    }
}
