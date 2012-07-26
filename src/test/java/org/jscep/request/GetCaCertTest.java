package org.jscep.request;

import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.Operation;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

public class GetCaCertTest {
    private GetCaCertRequest fixture;
    private String caIdentifier;

    @Before
    public void setUp() {
        caIdentifier = "id";
        fixture = new GetCaCertRequest(caIdentifier);
    }

    @Test
    public void testNullConstructor() {
        fixture = new GetCaCertRequest();
        Assert.assertEquals("", fixture.getMessage());
    }

    @Test
    public void testGetOperation() {
        Assert.assertSame(Operation.GET_CA_CERT, fixture.getOperation());
    }

    @Test
    public void testGetMessage() throws IOException {
        Assert.assertEquals(caIdentifier, fixture.getMessage());
    }

    @Test
    public void testString() {
        // Coverage
        fixture.toString();
    }
}
