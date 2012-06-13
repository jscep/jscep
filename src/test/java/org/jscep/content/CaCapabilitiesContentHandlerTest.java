package org.jscep.content;

import org.jscep.response.Capabilities;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.*;


public class CaCapabilitiesContentHandlerTest {
    private CaCapabilitiesContentHandler fixture;

    @Before
    public void setUp() {
        fixture = new CaCapabilitiesContentHandler();
    }

    @Test
    public void testContentTypeIgnored() throws InvalidContentTypeException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getContent(is, "foo/bar");
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void testNullContentTypeIgnored() throws InvalidContentTypeException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getContent(is, null);
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void testCorrectContentType() throws InvalidContentTypeException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getContent(is, "text/plain");
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void charsetIsIgnored() throws InvalidContentTypeException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getContent(is, "text/plain;charset=UTF-8");

        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    private byte[] getBytesForCapabilities(String... capabilities) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        final BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(baos));
        for (String capability : capabilities) {
            try {
				writer.write(capability);
				writer.write('\n');
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
        }
        try {
			writer.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

        return baos.toByteArray();
    }

}
