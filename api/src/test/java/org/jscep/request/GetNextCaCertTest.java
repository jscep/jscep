package org.jscep.request;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GetNextCaCertTest {
	private GetNextCaCert fixture;
	private String caIdentifier;
	
	@Before
	public void setUp() {
		caIdentifier = "id";
		fixture = new GetNextCaCert(caIdentifier);
	}
	
	@Test
	public void testGetOperation() {
		Assert.assertSame(Operation.GET_NEXT_CA_CERT, fixture.getOperation());
	}

	@Test
	public void testGetMessage() throws IOException {
		Assert.assertEquals(caIdentifier, fixture.getMessage());
	}
}
