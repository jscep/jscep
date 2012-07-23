package org.jscep.client;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class ClientExceptionTest {

    @Test
    public void testClientExceptionCause() {
        Throwable cause = new Exception();
        ClientException e = new ClientException(cause);
        
        assertThat(e.getCause(), is(cause));
    }

    @Test
    public void testClientExceptionMessage() {
        String message = "message";
        ClientException e = new ClientException(message);
        
        assertThat(e.getMessage(), is(message));
    }

}
