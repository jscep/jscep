package org.jscep.transport;

import com.sun.net.ssl.internal.ssl.SSLSocketFactoryImpl;
import org.junit.Test;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;

import static org.junit.Assert.assertTrue;

public class TransportFactoryFactoryTest {

    @Test
    public void testGetTransportFactoryWithHttpsAndSslSocketFactory() throws Exception {
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("https://localhost/test"), new DummySslSocketFactory());

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
        final TransportFactory transportFactory = TransportFactoryFactory.getTransportFactory(new URL("http://localhost/test"), new DummySslSocketFactory());

        assertTrue(transportFactory instanceof UrlConnectionTransportFactory);
    }

    private class DummySslSocketFactory extends SSLSocketFactory{
        @Override
        public String[] getDefaultCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
            return null;
        }

        @Override
        public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
            return null;
        }

        @Override
        public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
            return null;
        }

        @Override
        public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
            return null;
        }

        @Override
        public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
            return null;
        }
    }
}