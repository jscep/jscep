package org.jscep.transport;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class SniHostNameTest {
    private URL exampleUrl;
    private static SNIHostName exampleSni;

    @Before
    public void setUp() throws MalformedURLException {
        exampleUrl = new URL("https://www.example.com");
        exampleSni = new SNIHostName(exampleUrl.getHost());
    }

    @Test
    public void testPostTransportSetsSNI() throws IOException {
        UrlConnectionPostTransport transport = new UrlConnectionPostTransport(exampleUrl);
        SSLSocketFactory socketFactory = transport.getSslSocketFactory();
        SSLSocket socket  = (SSLSocket)socketFactory.createSocket();

        final SSLParameters sslParameters = socket.getSSLParameters();
        final List<SNIServerName> serverNames = sslParameters.getServerNames();

        Assert.assertEquals(serverNames.size(), 1);
        Assert.assertEquals(serverNames.get(0), exampleSni);
    }

    @Test
    public void testGetTransportSetsSNI() throws IOException {
        UrlConnectionGetTransport transport = new UrlConnectionGetTransport(exampleUrl);
        SSLSocketFactory socketFactory = transport.getSslSocketFactory();
        SSLSocket socket  = (SSLSocket)socketFactory.createSocket();

        final SSLParameters sslParameters = socket.getSSLParameters();
        final List<SNIServerName> serverNames = sslParameters.getServerNames();

        Assert.assertEquals(serverNames.size(), 1);
        Assert.assertEquals(serverNames.get(0), exampleSni);
    }
}
