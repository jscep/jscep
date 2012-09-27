package org.jscep.transaction;

import org.junit.Assert;
import org.junit.Test;

public class MessageTypeTest {
    @Test
    public void testValueOf() {
        for (MessageType msgType : MessageType.values()) {
            Assert.assertSame(msgType, MessageType.valueOf(msgType.getValue()));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalid() {
        MessageType.valueOf(-1);
    }
}
