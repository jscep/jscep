package com.google.code.jscep.content;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.code.jscep.response.Capability;

public class CaCapabilitiesContentHandlerTest {
	private CaCapabilitiesContentHandler fixture;
	
	@Before
	public void setUp() {
		 fixture = new CaCapabilitiesContentHandler();
	}
	
	@Test
	public void testContentTypeIgnored() throws IOException {
		final InputStream is = getStreamForCapabilities("DES3");
		final Set<Capability> caps = fixture.getContent(is, "foo/bar");
		Assert.assertTrue(caps.contains(Capability.TRIPLE_DES));
	}
	
	@Test
	public void testCorrectContentType() throws IOException {
		final InputStream is = getStreamForCapabilities("DES3");
		final Set<Capability> caps = fixture.getContent(is, "text/plain");
		Assert.assertTrue(caps.contains(Capability.TRIPLE_DES));
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
