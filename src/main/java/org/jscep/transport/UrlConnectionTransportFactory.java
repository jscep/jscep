package org.jscep.transport;

import java.net.URL;

/**
 * Created with IntelliJ IDEA.
 * User: david
 * Date: 23/01/2013
 * Time: 21:56
 * To change this template use File | Settings | File Templates.
 */
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
