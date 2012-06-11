package org.jscep.util;

import static org.junit.Assert.fail;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;

public class LoggingUtilTest {
	private Logger fixture;
	
	@Before
	public void setUp() {
		fixture = LoggingUtil.getLogger(LoggingUtil.class);
	}
	
	@Test
	public void testGetLoggerClass() {
		Assert.assertEquals(fixture, LoggingUtil.getLogger(LoggingUtil.class));
	}
	
	@Test
	public void testIssue62() throws Exception {
		try {
			LoggingUtil.getLogger(Class.forName("NoPackageTestFixture"));
		} catch (NullPointerException e) {
			fail("Should not have thrown a null pointer exception.");
		}
	}

}
