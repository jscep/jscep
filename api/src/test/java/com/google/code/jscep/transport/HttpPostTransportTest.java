package com.google.code.jscep.transport;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.jscep.request.GetCACaps;
import org.jscep.request.GetCACert;
import org.jscep.request.GetNextCACert;
import org.jscep.transport.Transport;
import org.jscep.transport.Transport.Method;
import org.jscep.x509.X509Util;
import org.junit.Before;
import org.junit.Test;


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
	
	@Test(expected = IllegalArgumentException.class)
	public void testGetCACert() throws IOException {
		transport.sendMessage(new GetCACert(null));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testGetCACaps() throws IOException {
		transport.sendMessage(new GetCACaps(null));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testGetNextCACert() throws IOException, GeneralSecurityException {
		X500Principal subject = new X500Principal("CN=example.org");
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		X509Certificate cert = X509Util.createEphemeralCertificate(subject, keyPair);
		
		transport.sendMessage(new GetNextCACert(cert));
	}
}
