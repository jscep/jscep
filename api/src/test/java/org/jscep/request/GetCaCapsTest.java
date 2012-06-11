package org.jscep.request;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GetCaCapsTest {
	private GetCaCaps fixture;
	private String caIdentifier;
	
	@Before
	public void setUp() {
		caIdentifier = "id";
		fixture = new GetCaCaps(caIdentifier);
	}
	
	@Test
	public void testNullConstructor() {
		fixture = new GetCaCaps();
		Assert.assertEquals("", fixture.getMessage());
	}

	@Test
	public void testGetOperation() {
		Assert.assertSame(Operation.GET_CA_CAPS, fixture.getOperation());
	}

	@Test
	public void testGetMessage() throws IOException {
		Assert.assertEquals(caIdentifier, fixture.getMessage());
	}
	
	@Test
	public void testString() {
		// Coverage
		fixture.toString();
	}
}
