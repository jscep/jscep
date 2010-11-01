package org.jscep.transport;

import junit.framework.Assert;

import org.jscep.transport.Transport.Method;
import org.junit.Test;


public class HttpGetTransportTest extends AbstractTransportTest {
	@Test
	public void testGetURL() {
		Assert.assertEquals(url, transport.getURL());
	}

	@Override
	protected Method getMethod() {
		return Method.GET;
	}
}
