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
	
	@Before
	public void setUp() {
		fixture = new ClientConfiguration();
	}
	
	@Test
	public void testGetUrl() throws MalformedURLException {
		URL url = new URL("http://www.example.org/");
		fixture.setUrl(url);
		Assert.assertEquals(url, fixture.getUrl());
	}

	@Test
	public void testGetProxy() {
		Proxy proxy = Proxy.NO_PROXY;
		fixture.setProxy(proxy);
		Assert.assertEquals(proxy, fixture.getProxy());
	}

	@Test
	public void testGetCaId() {
		String id = "ID";
		fixture.setCaId(id);
		Assert.assertEquals(id, fixture.getCaId());
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
		fixture.setDigestAlgorithm(alg);
		Assert.assertEquals(alg, fixture.getDigestAlgorithm());
	}

}
