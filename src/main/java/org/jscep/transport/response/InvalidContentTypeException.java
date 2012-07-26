package org.jscep.transport.response;

import java.util.Arrays;

import net.jcip.annotations.Immutable;

/**
 * <tt>InvalidContentTypeException</tt> is thrown if the HTTP
 * <tt>Content-Type</tt> header sent by the server does not match the value
 * expected by a {@link ScepResponseHandler}.
 */
@Immutable
public class InvalidContentTypeException extends ContentException {
    private static final long serialVersionUID = 8144078591967730995L;

    public InvalidContentTypeException(final String actual,
            final String... expected) {
        this(String.format("Expected %s, but was %s",
                Arrays.toString(expected), actual));
    }

    public InvalidContentTypeException(Throwable cause) {
        super(cause);
    }

    public InvalidContentTypeException(String message) {
        super(message);
    }
}
