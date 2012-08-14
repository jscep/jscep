package org.jscep.message;

import static org.junit.Assert.*;

import org.junit.Test;

public class MessageDecodingExceptionTest {

    @Test
    public void testMessageDecodingExceptionThrowable() {
	Throwable t = new Exception();
	MessageDecodingException e = new MessageDecodingException(t);
	assertSame(t, e.getCause());
    }

    @Test
    public void testMessageDecodingExceptionString() {
	String m = "message";
	MessageDecodingException e = new MessageDecodingException(m);
	assertSame(m, e.getMessage());
    }
}
