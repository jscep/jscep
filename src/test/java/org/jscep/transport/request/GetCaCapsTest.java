package org.jscep.transport.request;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GetCaCapsTest {
    private GetCaCapsRequest fixture;
    private String caIdentifier;

    @Before
    public void setUp() {
        caIdentifier = "id";
        fixture = new GetCaCapsRequest(caIdentifier);
    }

    @Test
    public void testNullConstructor() {
        fixture = new GetCaCapsRequest();
        Assert.assertEquals("", fixture.getMessage());
    }

    @Test
    public void testGetOperation() {
        Assert.assertSame(Operation.GET_CA_CAPS, fixture.getOperation());
    }

    @Test
    public void testGetMessage() {
        Assert.assertEquals(caIdentifier, fixture.getMessage());
    }

    @Test
    public void testString() {
        // Coverage
        fixture.toString();
    }
}
