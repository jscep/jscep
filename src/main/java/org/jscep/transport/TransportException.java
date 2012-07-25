package org.jscep.transport;

import net.jcip.annotations.Immutable;

/**
 * <tt>TransportException</tt> is thrown by the transport layer for any networking issues.
 */
@Immutable
public class TransportException extends Exception {
    /**
	 * 
	 */
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
