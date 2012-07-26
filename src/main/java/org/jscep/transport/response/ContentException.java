package org.jscep.transport.response;

public class ContentException extends Exception {
    private static final long serialVersionUID = -959127316844320818L;

    public ContentException(Throwable cause) {
        super(cause);
    }

    public ContentException(String message) {
        super(message);
    }

}
