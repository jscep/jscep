package org.jscep.transport.response;

import org.jscep.transport.response.InvalidContentTypeException;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.junit.Before;
import org.junit.Test;

public class CertRepContentHandlerTest {
    private PkiOperationResponseHandler fixture;

    @Before
    public void setUp() throws Exception {
	fixture = new PkiOperationResponseHandler();
    }

    @Test(expected = InvalidContentTypeException.class)
    public void testInvalidMime() throws Exception {
	fixture.getResponse(new byte[0], "text/plain");
    }
}
