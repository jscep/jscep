package org.jscep.transaction;

import org.junit.Assert;
import org.junit.Test;

public class PkiStatusTest {
    @Test
    public void testValueOf() {
	for (PkiStatus status : PkiStatus.values()) {
	    Assert.assertSame(status, PkiStatus.valueOf(status.getValue()));
	}
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalid() {
	PkiStatus.valueOf(-1);
    }
}
