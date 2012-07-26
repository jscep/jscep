package org.jscep.content;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import org.jscep.transport.response.InvalidContentException;
import org.junit.Test;

public class InvalidContentExceptionTest {

    @Test
    public void testInvalidContentExceptionCause() {
        Throwable cause = new Exception();
        InvalidContentException e = new InvalidContentException(cause);
        
        assertThat(e.getCause(), is(cause));
    }

    @Test
    public void testInvalidContentExceptionMessage() {
        String message = "message";
        InvalidContentException e = new InvalidContentException(message);
        
        assertThat(e.getMessage(), is(message));
    }

}
