package com.google.code.jscep;

import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.easymock.classextension.EasyMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ClientConfigurationTest {
	private ClientConfiguration fixture;
	private URL url;
	private Proxy proxy;
	
	@Before
	public void setUp() throws MalformedURLException {
		url = new URL("http://www.example.org/");
		proxy = Proxy.NO_PROXY;
		fixture = new ClientConfiguration(url, proxy);
	}
	
	@Test
	public void testGetUrl() throws MalformedURLException {
		Assert.assertEquals(url, fixture.getUrl());
	}

	@Test
	public void testGetProxy() {
		Assert.assertEquals(proxy, fixture.getProxy());
	}

	@Test
	public void testGetCaId() {
		String id = "ID";
		fixture.setCaIdentifier(id);
		Assert.assertEquals(id, fixture.getCaIdentifier());
	}

	@Test
	public void testGetKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		fixture.setKeyPair(keyPair);
		Assert.assertEquals(keyPair, fixture.getKeyPair());
	}

	@Test
	public void testGetSubject() {
		X500Principal subject = new X500Principal("CN=example.org"); 
		fixture.setSubject(subject);
		Assert.assertEquals(subject, fixture.getSubject());
	}

	@Test
	public void testGetIdentity() {
		X509Certificate cert = EasyMock.createMock(X509Certificate.class);
		fixture.setIdentity(cert);
		Assert.assertEquals(cert, fixture.getIdentity());
	}

	@Test
	public void testGetCaDigest() {
		byte[] digest = new byte[0];
		fixture.setCaDigest(digest);
		Assert.assertEquals(digest, fixture.getCaDigest());
	}

	@Test
	public void testGetCaCertificate() {
		X509Certificate cert = EasyMock.createMock(X509Certificate.class);
		fixture.setCaCertificate(cert);
		Assert.assertEquals(cert, fixture.getCaCertificate());
	}

	@Test
	public void testGetDigestAlgorithm() {
		String alg = "MD5";
		fixture.setCaDigest(new byte[0], alg);
		Assert.assertEquals(alg, fixture.getDigestAlgorithm());
	}

}
