package org.jscep.request;

import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.request.Operation;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

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
    public void testGetMessage() throws IOException {
        Assert.assertEquals(caIdentifier, fixture.getMessage());
    }
}
