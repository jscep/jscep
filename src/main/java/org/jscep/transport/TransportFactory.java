package org.jscep.transport;

import java.net.URL;

public interface TransportFactory {
    public static enum Method {
        GET,
        POST
    }

    Transport forMethod(Method method, URL url);
}
