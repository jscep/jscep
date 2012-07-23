package org.jscep.transport;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class TransportExceptionTest {
    
    private String message;
    private Throwable cause;

    @Before
    public void setUp() {
        message = "message";
        cause = new Exception();
    }

    @Test
    public void testTransportExceptionMessageCause() {
        TransportException e = new TransportException(message, cause);
        
        assertThat(e.getMessage(), is(message));
        assertThat(e.getCause(), is(cause));
    }

    @Test
    public void testTransportExceptionCause() {
        TransportException e = new TransportException(cause);
        
        assertThat(e.getCause(), is(cause));
    }

    @Test
    public void testTransportExceptionMessage() {
        TransportException e = new TransportException(message);
        
        assertThat(e.getMessage(), is(message));
    }

}
