package org.jscep.content;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Before;
import org.junit.Test;

public class CertRepContentHandlerTest {
	private CertRepContentHandler fixture;
	
	@Before
	public void setUp() throws Exception {
		fixture = new CertRepContentHandler();
	}

	@Test(expected=IOException.class)
	public void testInvalidMime() throws Exception {
		InputStream in = new ByteArrayInputStream(new byte[0]);
		fixture.getContent(in, "text/plain");
	}
}
