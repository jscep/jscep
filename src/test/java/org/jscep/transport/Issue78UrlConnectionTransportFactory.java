package org.jscep.transport;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

public class Issue78UrlConnectionTransportFactory implements TransportFactory {

    private SSLSocketFactory sslSocketFactory;

    public Issue78UrlConnectionTransportFactory(){}

    public Issue78UrlConnectionTransportFactory(SSLSocketFactory sslSocketFactory){
        this.sslSocketFactory = sslSocketFactory;
    }

    @Override
    public Transport forMethod(Method method, URL url) {
        if (method == Method.GET) {
            return new Issue78UrlConnectionGetTransport(url, sslSocketFactory);
        } else {
            return new UrlConnectionPostTransport(url, sslSocketFactory);
        }
    }
}
