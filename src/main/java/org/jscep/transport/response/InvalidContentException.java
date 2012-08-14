package org.jscep.transport.response;

import net.jcip.annotations.Immutable;

/**
 * <tt>InvalidContentException</tt> is thrown if a {@link ScepResponseHandler}
 * is unable to parse the content returned by the SCEP server.
 */
@Immutable
public class InvalidContentException extends ContentException {
    /**
     * 
     */
    private static final long serialVersionUID = 8144078591967730995L;

    public InvalidContentException(Throwable cause) {
	super(cause);
    }

    public InvalidContentException(String message) {
	super(message);
    }
}
