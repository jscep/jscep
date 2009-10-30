package com.google.code.jscep.transport;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

import com.google.code.jscep.request.Request;

/**
 * HTTP GET
 */
public class HttpGetTransport extends Transport {
	protected HttpGetTransport(URL url, Proxy proxy) {
		super(url, proxy);
	}
	
	@Override
	public Object sendMessage(Request msg) throws IOException, MalformedURLException {
		URL url = getUrl(msg.getOperation(), msg.getMessage());
        URLConnection conn = url.openConnection(proxy);

        return conn.getContent();
	}
	
	private URL getUrl(String op, Object message) throws MalformedURLException {
        if (message == null) {
            return new URL(getUrl(op).toExternalForm() + "&message=");
        } else {
            return new URL(getUrl(op).toExternalForm() + "&message=" + message);
        }
    }

}
