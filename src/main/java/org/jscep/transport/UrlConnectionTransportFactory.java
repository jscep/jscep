package org.jscep.transport;

import java.net.URL;

public class UrlConnectionTransportFactory implements TransportFactory {
    @Override
    public Transport forMethod(Method method, URL url) {
        if (method == Method.GET) {
            return new UrlConnectionGetTransport(url);
        } else {
            return new UrlConnectionPostTransport(url);
        }
    }
}
