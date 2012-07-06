package org.jscep.content;

import java.util.Arrays;

public class InvalidContentException extends Exception {
    /**
     * 
     */
    private static final long serialVersionUID = 8144078591967730995L;

    public InvalidContentException(String actual, String... expected) {
        this(String.format("Expected %s, but was %s",
                Arrays.toString(expected), actual));
    }

    public InvalidContentException(Throwable cause) {
        super(cause);
    }

    public InvalidContentException(String message) {
        super(message);
    }
}
