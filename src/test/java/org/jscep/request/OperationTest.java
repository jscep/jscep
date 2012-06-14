package org.jscep.request;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class OperationTest {

	@Test(expected = NullPointerException.class)
	public void testForNullName() {
		Operation.forName(null);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testForInvalidName() {
		Operation.forName("invalid");
	}
	
	@Test
	public void testForNameEnumeration() {
		for (Operation op : Operation.values()) {
			assertThat(op, is(Operation.forName(op.getName())));
		}
	}

}
