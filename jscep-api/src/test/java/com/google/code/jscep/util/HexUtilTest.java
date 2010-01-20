package com.google.code.jscep.util;

import org.junit.Assert;
import org.junit.Test;


public class HexUtilTest {
	@Test
	public void simpleTest() {
		byte[] bytes = new byte[] {0, 1, 2, 3, 4};
		Assert.assertArrayEquals(bytes, HexUtil.fromHex(HexUtil.toHex(bytes)));
	}
}
