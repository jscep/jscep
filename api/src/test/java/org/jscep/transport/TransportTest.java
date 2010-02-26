package org.jscep.transport;

import java.net.URL;

import org.jscep.transport.Transport.Method;
import org.junit.Assert;
import org.junit.Test;

public class TransportTest {

	@Test
	public void testCreateTransportPost() throws Exception {
		Transport t = Transport.createTransport(Method.POST, new URL("http://example.org/"));
		Assert.assertTrue(t instanceof HttpPostTransport);
	}
	
	@Test
	public void testCreateTransportGet() throws Exception {
		Transport t = Transport.createTransport(Method.GET, new URL("http://example.org/"));
		Assert.assertTrue(t instanceof HttpGetTransport);
	}

}
