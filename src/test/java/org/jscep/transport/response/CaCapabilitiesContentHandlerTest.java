package org.jscep.transport.response;

import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.ContentException;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.*;

public class CaCapabilitiesContentHandlerTest {
    private GetCaCapsResponseHandler fixture;

    @Before
    public void setUp() {
        fixture = new GetCaCapsResponseHandler();
    }

    @Test
    public void testContentTypeIgnored() throws ContentException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getResponse(is, "foo/bar");
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void testNullContentTypeIgnored() throws ContentException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getResponse(is, null);
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void testCorrectContentType() throws ContentException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getResponse(is, "text/plain");
        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    @Test
    public void charsetIsIgnored() throws ContentException {
        final byte[] is = getBytesForCapabilities("DES3");
        final Capabilities caps = fixture.getResponse(is,
                "text/plain;charset=UTF-8");

        Assert.assertEquals("DESede", caps.getStrongestCipher());
    }

    private byte[] getBytesForCapabilities(String... capabilities) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();

        final BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(baos));
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
