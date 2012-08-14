package org.jscep.message;

import static org.junit.Assert.*;

import org.junit.Test;

public class MessageEncodingExceptionTest {

    @Test
    public void testMessageEncodingExceptionThrowable() {
	Throwable t = new Exception();
	MessageEncodingException e = new MessageEncodingException(t);
	assertSame(t, e.getCause());
    }

    @Test
    public void testMessageEncodingExceptionString() {
	String m = "message";
	MessageEncodingException e = new MessageEncodingException(m);
	assertSame(m, e.getMessage());
    }
}
