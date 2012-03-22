package org.jscep.util;

import org.junit.Assert;
import org.junit.Test;


public class HexUtilTest {
	@Test
	public void testSimple() {
		byte[] bytes = new byte[] {0, 1, 2, 3, 4};
		Assert.assertArrayEquals(bytes, HexUtil.fromHex(HexUtil.toHex(bytes)));
	}
	
	@Test
	public void testString() {
		byte[] bytes = HexUtil.fromHex("FF00CC");
		Assert.assertSame(3, bytes.length);
		Assert.assertSame((byte) -1, bytes[0]);
		Assert.assertSame((byte) 0, bytes[1]);
		Assert.assertSame((byte) 204, bytes[2]);
	}
}
