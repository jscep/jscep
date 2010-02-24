package org.jscep.pkcs9;

import junit.framework.Assert;

import org.jscep.pkcs9.ChallengePasswordAttribute;
import org.junit.Before;
import org.junit.Test;

public class ChallengePasswordTest {
	private String password = "password";
	private ChallengePasswordAttribute fixture;
	
	@Before
	public void setup() {
		this.fixture = new ChallengePasswordAttribute(password);
	}
	
	@Test
	public void testGetPassword() {
		Assert.assertEquals(password, fixture.getPassword());
	}

}
