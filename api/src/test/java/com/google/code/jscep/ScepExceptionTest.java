package com.google.code.jscep;

import org.junit.Assert;
import org.junit.Test;

public class ScepExceptionTest {

	@Test
	public void testScepException() {
		ScepException e = new ScepException();
		Assert.assertNull(e.getMessage());
		Assert.assertNull(e.getCause());
	}

	@Test
	public void testScepExceptionString() {
		ScepException e = new ScepException("Message");
		Assert.assertSame("Message", e.getMessage());
		Assert.assertNull(e.getCause());
	}

	@Test
	public void testScepExceptionStringThrowable() {
		Exception c = new Exception();
		ScepException e = new ScepException("Message", c);
		Assert.assertEquals("Message", e.getMessage());
		Assert.assertEquals(c, e.getCause());
	}

	@Test
	public void testScepExceptionThrowable() {
		Exception c = new Exception();
		ScepException e = new ScepException(c);
		Assert.assertEquals("java.lang.Exception", e.getMessage());
		Assert.assertEquals(c, e.getCause());
	}

}
