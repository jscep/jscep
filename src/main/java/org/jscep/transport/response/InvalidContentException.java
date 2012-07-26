package org.jscep.transport.response;


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
