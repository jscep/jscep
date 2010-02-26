package org.jscep.request;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GetCACertTest {
	private GetCACert fixture;
	private String caIdentifier;
	
	@Before
	public void setUp() {
		caIdentifier = "id";
		fixture = new GetCACert(caIdentifier);
	}
	
	@Test
	public void testNullConstructor() {
		fixture = new GetCACert();
		Assert.assertNull(fixture.getMessage());
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
	
	@Test
	public void testString() {
		// Coverage
		fixture.toString();
	}
}
