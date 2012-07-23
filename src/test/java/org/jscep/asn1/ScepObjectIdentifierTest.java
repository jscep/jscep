package org.jscep.asn1;

import static org.junit.Assert.*;

import org.junit.Test;

public class ScepObjectIdentifierTest {
    @Test
    public void testValues() {
        for (ScepObjectIdentifier oid : ScepObjectIdentifier.values()) {
            assertSame(oid, ScepObjectIdentifier.valueOf(oid.name()));
        }
    }
}
