package org.jscep.transaction;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class InvalidNonceExceptionTest {
	private String msg;
	private InvalidNonceException exception;

	@Before
	public void setUp() {
		msg = "Message";
		exception = new InvalidNonceException(msg);
	}
	
	@Test
	public void testGetMessage() {
		assertThat(exception.getMessage(), is(msg));
	}
}
