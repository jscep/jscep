package org.jscep.transport;

import org.jscep.request.Operation;
import org.jscep.transport.Transport.Method;
import org.junit.Assert;
import org.junit.Test;

import java.net.URL;

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

	@Test
	public void testGetURL() throws Exception {
		Transport t = Transport.createTransport(Method.GET, new URL("http://example.org/"));
		URL url = t.getUrl(Operation.GET_CA_CAPS);
		Assert.assertTrue(url.getQuery().contains("operation=" + Operation.GET_CA_CAPS.getName()));
	}
}
