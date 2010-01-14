package com.google.code.jscep.transaction;

import junit.framework.Assert;

import org.junit.Test;

public class CmsExceptionTest {

	@Test
	public void testCmsException() {
		CmsException e = new CmsException();
		assertCause(e, null);
	}

	@Test
	public void testCmsExceptionString() {
		CmsException e = new CmsException("msg");
		
		assertMessage(e, "msg");
	}

	@Test
	public void testCmsExceptionStringThrowable() {
		Throwable t = new Exception();
		CmsException e = new CmsException("msg", t);
		
		assertCause(e, t);
		assertMessage(e, "msg");
	}

	@Test
	public void testCmsExceptionThrowable() {
		Throwable t = new Exception();
		CmsException e = new CmsException("msg", t);
		
		assertCause(e, t);
	}

	private void assertCause(CmsException exception, Throwable cause) {
		Assert.assertEquals(cause, exception.getCause());
	}
	
	private void assertMessage(CmsException exception, String msg) {
		Assert.assertEquals(msg, exception.getMessage());
	}
}
