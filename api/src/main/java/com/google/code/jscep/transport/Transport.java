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
import java.util.logging.Logger;

import com.google.code.jscep.request.Operation;
import com.google.code.jscep.request.Request;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class represents the transport for sending a message to the SCEP server.
 */
public abstract class Transport {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transport");
	/**
	 * Represents the <tt>HTTP</tt> method to be used for transport. 
	 */
	public enum Method {
		/**
		 * The <tt>HTTP</tt> <tt>GET</tt> method.
		 */
		GET,
		/**
		 * The <tt>HTTP</tt> <tt>POST</tt> method.
		 */
		POST
	}
	final URL url;
	final Proxy proxy;
	
	Transport(URL url, Proxy proxy) {
		this.url = url;
		this.proxy = proxy;
	}
	
	/**
	 * Returns the URL configured for use by this transport.
	 * 
	 * @return the URL.
	 */
	public URL getURL() {
		return url;
	}
	
	/**
	 * Returns the proxy configured for use by this transport.
	 * 
	 * @return the proxy.
	 */
	public Proxy getProxy() {
		return proxy;
	}
	
	/**
	 * This method sends the given request to the URL provided in the constructor and
	 * uses the request's content handler to parse the response.  
	 * 
	 * @param <T> the response type.
	 * @param msg the message to send.
	 * @return the response of type T.
	 * @throws IOException if any I/O error occurs.
	 */
	abstract public <T> T sendMessage(Request<T> msg) throws IOException;
	
	/**
	 * Create a new transport of type <tt>method</tt>.
	 * 
	 * @param method the transport type.
	 * @param url the url.
	 * @param proxy the proxy.
	 * @return a new Transport instance.
	 */
	public static Transport createTransport(Method method, URL url, Proxy proxy) {
		LOGGER.entering(Transport.class.getName(), "createTransport", new Object[] { method, url, proxy });
		
		Transport t;
		
		if (method.equals(Method.GET)) {
			t = new HttpGetTransport(url, proxy);
		} else {
			t = new HttpPostTransport(url, proxy);
		}
		
		LOGGER.exiting(Transport.class.getName(), "createTransport", t);
		return t;
	}
	
	URL getUrl(Operation op) throws MalformedURLException {
		return new URL(url.toExternalForm() + "?operation=" + op);
	}
}
