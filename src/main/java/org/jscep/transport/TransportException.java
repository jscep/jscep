package org.jscep.transport;

import net.jcip.annotations.Immutable;

/**
 * The <tt>TransportException</tt> is the base exception thrown when errors
 * occur in the transport layer, including networking errors and errors relating
 * to content.
 */
@Immutable
public class TransportException extends Exception {
    private static final long serialVersionUID = 7384278241045962726L;

    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }

    public TransportException(Throwable cause) {
        super(cause);
    }

    public TransportException(String message) {
        super(message);
    }
}
