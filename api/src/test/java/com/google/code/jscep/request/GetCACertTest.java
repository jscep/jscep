package com.google.code.jscep.request;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.jscep.request.GetCACert;
import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GetCACertTest {
	private Request<List<X509Certificate>> fixture;
	private String caIdentifier;
	
	@Before
	public void setUp() {
		caIdentifier = "id";
		fixture = new GetCACert(caIdentifier);
	}
	
	@Test
	public void testGetOperation() {
		Assert.assertSame(Operation.GetCACert, fixture.getOperation());
	}

	@Test
	public void testGetMessage() throws IOException {
		Assert.assertEquals(caIdentifier, fixture.getMessage());
	}

	@Test
	public void testContentHandler() {
		Assert.assertNotNull(fixture.getContentHandler());
	}
}
