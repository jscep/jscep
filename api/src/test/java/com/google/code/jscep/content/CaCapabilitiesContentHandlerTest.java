package com.google.code.jscep.content;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;

import org.jscep.content.CaCapabilitiesContentHandler;
import org.jscep.response.Capabilities;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class CaCapabilitiesContentHandlerTest {
	private CaCapabilitiesContentHandler fixture;
	
	@Before
	public void setUp() {
		 fixture = new CaCapabilitiesContentHandler();
	}
	
	@Test
	public void testContentTypeIgnored() throws IOException {
		final InputStream is = getStreamForCapabilities("DES3");
		final Capabilities caps = fixture.getContent(is, "foo/bar");
		Assert.assertEquals("DESede", caps.getStrongestCipher());
	}
	
	@Test
	public void testCorrectContentType() throws IOException {
		final InputStream is = getStreamForCapabilities("DES3");
		final Capabilities caps = fixture.getContent(is, "text/plain");
		Assert.assertEquals("DESede", caps.getStrongestCipher());
	}
	
	private InputStream getStreamForCapabilities(String... capabilities) throws IOException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		final BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos));
		for (String capability : capabilities) {
			writer.write(capability);
			writer.write('\n');
		}
		writer.close();
		
		return new ByteArrayInputStream(baos.toByteArray());
	}

}
