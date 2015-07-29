package org.jscep.transport;

import com.sun.net.ssl.internal.ssl.SSLSocketFactoryImpl;
import org.junit.Test;

import java.net.URL;

import static org.junit.Assert.assertTrue;

public class TransportFactoryFactoryTest {

    @Test
    public void testGetTransportFactoryWithHttpsAndSslSocketFactory() throws Exception {
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("https://localhost/test"), new SSLSocketFactoryImpl());

        assertTrue(transportFactory instanceof UrlConnectionWithSSLTransportFactory);
    }

    @Test
    public void testGetTransportFactoryWithHttpsAndWithoutSslSocketFactory() throws Exception {
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("https://localhost/test"), null);

        assertTrue(transportFactory instanceof UrlConnectionTransportFactory);
    }

    @Test
    public void testGetTransportFactoryWithoutHttpsAndSslSocketFactory() throws Exception {
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("http://localhost/test"), null);

        assertTrue(transportFactory instanceof UrlConnectionTransportFactory);
    }

    @Test
    public void testGetTransportFactoryWithoutHttpsAndWitSslSocketFactory() throws Exception {
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("http://localhost/test"), new SSLSocketFactoryImpl());

        assertTrue(transportFactory instanceof UrlConnectionTransportFactory);
    }
}