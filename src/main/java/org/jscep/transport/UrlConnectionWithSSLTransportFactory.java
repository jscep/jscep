package org.jscep.transport;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

/**
 * Creates instances of {@link org.jscep.transport.Transport} with SSL support
 */
public class UrlConnectionWithSSLTransportFactory implements TransportFactory {

    private final SSLSocketFactory sslSocketFactory;

    public UrlConnectionWithSSLTransportFactory(final SSLSocketFactory sslSocketFactory){
        this.sslSocketFactory = sslSocketFactory;
    }

    @Override
    public Transport forMethod(Method method, URL url) {
        if (method == Method.GET) {
            return new UrlConnectionGetWithSSLTransport(url, sslSocketFactory);
        } else {
            return new UrlConnectionPostWithSSLTransport(url, sslSocketFactory);
        }
    }
}
