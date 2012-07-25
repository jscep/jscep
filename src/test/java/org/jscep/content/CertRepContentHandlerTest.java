package org.jscep.content;

import org.junit.Before;
import org.junit.Test;

public class CertRepContentHandlerTest {
    private PkcsReqResponseHandler fixture;

    @Before
    public void setUp() throws Exception {
        fixture = new PkcsReqResponseHandler();
    }

    @Test(expected = InvalidContentTypeException.class)
    public void testInvalidMime() throws Exception {
        fixture.getResponse(new byte[0], "text/plain");
    }
}
