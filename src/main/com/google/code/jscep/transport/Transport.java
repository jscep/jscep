package com.google.code.jscep.transport;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;

import com.google.code.jscep.request.Request;

public abstract class Transport {
	protected final URL url;
	protected final Proxy proxy;
	
	protected Transport(URL url, Proxy proxy) {
		this.url = url;
		this.proxy = proxy;
	}
	
	abstract public Object sendMessage(Request msg) throws IOException, MalformedURLException;
	
	public static Transport createTransport(String method, URL url, Proxy proxy) {
		if (method.equals("GET")) {
			return new HttpGetTransport(url, proxy);
		} else {
			return new HttpPostTransport(url, proxy);
		}
	}
	
	protected URL getUrl(String op) throws MalformedURLException {
        return new URL(url.toExternalForm() + "?operation=" + op);
    }
}
