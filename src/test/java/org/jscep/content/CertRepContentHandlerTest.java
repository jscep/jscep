package org.jscep.content;

import org.junit.Before;
import org.junit.Test;

public class CertRepContentHandlerTest {
    private CertRepContentHandler fixture;

    @Before
    public void setUp() throws Exception {
        fixture = new CertRepContentHandler();
    }

    @Test(expected = InvalidContentTypeException.class)
    public void testInvalidMime() throws Exception {
        fixture.getContent(new byte[0], "text/plain");
    }
}
