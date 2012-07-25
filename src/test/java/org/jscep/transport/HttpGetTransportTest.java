package org.jscep.transport;

import java.net.URL;

import junit.framework.Assert;

import org.junit.Test;

public class HttpGetTransportTest extends AbstractTransportTest {
    @Test
    public void testGetURL() {
        Assert.assertEquals(url, transport.getUrl());
    }

    @Override
    protected Transport getTransport(URL url) {
        return new HttpGetTransport(url);
    }
}
