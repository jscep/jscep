package com.google.code.jscep;

import junit.framework.Assert;

import org.jscep.PKIOperationFailureException;
import org.jscep.transaction.FailInfo;
import org.junit.Before;
import org.junit.Test;


public class PKIOperationFailureExceptionTest {
	private PKIOperationFailureException fixture;
	private FailInfo failInfo;
	
	@Before
	public void setup() {
		failInfo = FailInfo.badAlg;
		fixture = new PKIOperationFailureException(failInfo);
	}

	@Test
	public void testGetFailInfo() {
		Assert.assertSame(failInfo, fixture.getFailInfo());
	}

}
