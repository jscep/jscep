/*
 * Copyright (c) 2009 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.google.code.jscep.transport;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

import com.google.code.jscep.content.ScepContentHandlerFactory;
import com.google.code.jscep.request.Request;

/**
 * This class represents the transport for sending a message to the SCEP server.
 */
public abstract class Transport {
    static {
        URLConnection.setContentHandlerFactory(new ScepContentHandlerFactory());
    }
	public enum Method {
		GET,
		POST
	}
	protected final URL url;
	protected final Proxy proxy;
	
	Transport(URL url, Proxy proxy) {
		this.url = url;
		this.proxy = proxy;
	}
	
	public URL getURL() {
		return url;
	}
	public Proxy getProxy() {
		return proxy;
	}
	abstract public Object sendMessage(Request msg) throws IOException, MalformedURLException;
	
	/**
	 * Create a new transport of type <tt>method</tt>.
	 * 
	 * @param method the transport type.
	 * @param url the url.
	 * @param proxy the proxy.
	 * @return a new Transport instance.
	 */
	public static Transport createTransport(Method method, URL url, Proxy proxy) {
		if (method.equals(Method.GET)) {
			return new HttpGetTransport(url, proxy);
		} else {
			return new HttpPostTransport(url, proxy);
		}
	}
	
	protected URL getUrl(String op) throws MalformedURLException {
        return new URL(url.toExternalForm() + "?operation=" + op);
    }
}
