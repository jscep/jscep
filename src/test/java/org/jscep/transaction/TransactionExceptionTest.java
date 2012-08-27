package org.jscep.transaction;

import static org.junit.Assert.*;

import org.junit.Test;

public class TransactionExceptionTest {

    @Test
    public void testTransactionExceptionThrowable() {
	Throwable cause = new Exception();
	TransactionException e = new TransactionException(cause);

	assertEquals(cause, e.getCause());

    }

    @Test
    public void testTransactionExceptionString() {
	String message = "message";
	TransactionException e = new TransactionException(message);

	assertEquals(message, e.getMessage());
    }
}
