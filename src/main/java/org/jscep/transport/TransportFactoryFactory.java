package org.jscep.transport;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

public class TransportFactoryFactory {

    public static TransportFactory getTransportFactory(URL url, SSLSocketFactory sslSocketFactory){
        if(url.getProtocol().matches("^https.*") && sslSocketFactory != null){
            return new UrlConnectionWithSSLTransportFactory(sslSocketFactory);
        } else {
            return new UrlConnectionTransportFactory();
        }
    }

}
