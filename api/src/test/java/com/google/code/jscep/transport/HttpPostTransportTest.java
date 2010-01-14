package com.google.code.jscep.transport;

import java.net.Proxy;
import java.net.URL;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import com.google.code.jscep.transport.Transport.Method;

public class HttpPostTransportTest {
	private URL url;
	private Proxy proxy;
	private Transport transport;
	
	@Before
	public void setUp() throws Exception {
		url = new URL("http://www.example.org/");
		proxy = Proxy.NO_PROXY;
		transport = Transport.createTransport(Method.POST, url, proxy);
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
