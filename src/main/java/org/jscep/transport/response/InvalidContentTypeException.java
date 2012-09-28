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

    /**
     * Creates a new <tt>InvalidContentTypeException</tt>.
     * <p>
     * This constructor is useful for capturing the content type (or types)
     * expected by the <tt>ScepResponseHandler</tt>, and the content type that
     * the SCEP server specified. For example:
     * 
     * <pre>
     * new InvalidContentTypeException(&quot;text/plain&quot;, &quot;application/x-x509-ca-cert&quot;);
     * </pre>
     * 
     * @param actual
     *            the content type specified by the server.
     * @param expected
     *            the content types expected by the <tt>ScepResponseHandler</tt>
     */
    public InvalidContentTypeException(final String actual,
            final String... expected) {
        this(String.format("Expected %s, but was %s",
                Arrays.toString(expected), actual));
    }

    /**
     * Creates a new <tt>InvalidContentTypeException</tt> for the provided
     * cause.
     * 
     * @param cause
     *            the cause of this error.
     */
    public InvalidContentTypeException(final Throwable cause) {
        super(cause);
    }

    private InvalidContentTypeException(final String message) {
        super(message);
    }
}
