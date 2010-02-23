package org.jscep.request;

import java.io.IOException;

import org.jscep.request.GetCACaps;
import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.jscep.response.Capabilities;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GetCACapsTest {
	private Request<Capabilities> fixture;
	private String caIdentifier;
	
	@Before
	public void setUp() {
		caIdentifier = "id";
		fixture = new GetCACaps(caIdentifier);
	}

	@Test
	public void testGetOperation() {
		Assert.assertSame(Operation.GetCACaps, fixture.getOperation());
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
