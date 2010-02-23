package com.google.code.jscep.transaction;

import org.jscep.transaction.FailInfo;
import org.junit.Assert;
import org.junit.Test;

public class FailInfoTest {

	@Test
	public void testValueOf() {
		for (FailInfo failInfo : FailInfo.values()) {
			Assert.assertSame(failInfo, FailInfo.valueOf(failInfo.getValue()));
		}
	}

	@Test(expected=IllegalArgumentException.class)
	public void testInvalid() {
		FailInfo.valueOf(-1);
	}
}
