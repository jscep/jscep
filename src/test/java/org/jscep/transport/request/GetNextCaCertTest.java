package org.jscep.transport.request;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GetNextCaCertTest {
    private GetNextCaCertRequest fixture;
    private String caIdentifier;

    @Before
    public void setUp() {
        caIdentifier = "id";
        fixture = new GetNextCaCertRequest(caIdentifier);
    }

    @Test
    public void testGetOperation() {
        Assert.assertSame(Operation.GET_NEXT_CA_CERT, fixture.getOperation());
    }

    @Test
    public void testGetMessage() {
        Assert.assertEquals(caIdentifier, fixture.getMessage());
    }
}
