package org.jscep.util;

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
	public void testGetLoggerString() {
		Assert.assertEquals(fixture, LoggingUtil.getLogger("org.jscep.util"));
	}

}
