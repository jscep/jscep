package org.jscep.client;

import junit.framework.Assert;

import org.jscep.transaction.FailInfo;
import org.junit.Before;
import org.junit.Test;


public class PKIOperationFailureExceptionTest {
	private PkiOperationFailureException fixture;
	private FailInfo failInfo;
	
	@Before
	public void setup() {
		failInfo = FailInfo.badAlg;
		fixture = new PkiOperationFailureException(failInfo);
	}

	@Test
	public void testGetFailInfo() {
		Assert.assertSame(failInfo, fixture.getFailInfo());
	}

}
