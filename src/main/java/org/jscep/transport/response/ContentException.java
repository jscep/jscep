package org.jscep.transport.response;

import net.jcip.annotations.Immutable;

import org.jscep.transport.TransportException;

/**
 * The <tt>ContentException</tt> is a specialised <tt>TransportException</tt>
 * which relates directly to invalid content being sent by a SCEP server.
 */
@Immutable
public class ContentException extends TransportException {
    private static final long serialVersionUID = -959127316844320818L;

    public ContentException(Throwable cause) {
        super(cause);
    }

    public ContentException(String message) {
        super(message);
    }

}
