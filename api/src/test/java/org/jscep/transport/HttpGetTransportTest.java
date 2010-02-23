package org.jscep.transport;

import java.net.Proxy;
import java.net.URL;

import junit.framework.Assert;

import org.jscep.transport.Transport;
import org.jscep.transport.Transport.Method;
import org.junit.Before;
import org.junit.Test;


public class HttpGetTransportTest {
	private URL url;
	private Proxy proxy;
	private Transport transport;
	
	@Before
	public void setUp() throws Exception {
		url = new URL("http://www.example.org/");
		proxy = Proxy.NO_PROXY;
		transport = Transport.createTransport(Method.GET, url, proxy);
	}
	
	@Test
	public void testGetURL() {
		Assert.assertEquals(url, transport.getURL());
	}

	@Test
	public void testGetProxy() {
		Assert.assertEquals(proxy, transport.getProxy());
	}
}
