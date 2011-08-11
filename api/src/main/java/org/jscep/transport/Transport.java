/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.transport;

import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;


/**
 * This class represents a transport for sending a message to the SCEP server.
 * <p>
 * Example usage:
 * <pre>
 * Request&lt;?&gt; req = ...;
 * URL url = new URL("http://www.example.org/scep/pki-client.exe");
 * Proxy proxy = Proxy.NO_PROXY;
 * Transport trans = Transport.createTransport(Transport.Method.POST, url, proxy);
 * Object res = trans.setMessage(req);
 * </pre>
 * 
 * @author David Grant
 */
public abstract class Transport {
    private static Logger LOGGER = LoggingUtil.getLogger(Transport.class);
	/**
	 * Represents the <code>HTTP</code> method to be used for transport. 
	 */
	public static enum Method {
		/**
		 * The <code>HTTP GET</code> method.
		 */
		GET,
		/**
		 * The <code>HTTP POST</code> method.
		 */
		POST
	}
	final URL url;
	
	Transport(URL url) {
		this.url = url;
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
	 * Sends the given request to the URL provided in the constructor and
	 * uses the {@link Request}'s content handler to parse the response.  
	 * 
	 * @param <T> the response type.
	 * @param msg the message to send.
	 * @return the response of type T.
	 * @throws IOException if any I/O error occurs.
	 * @see Request#getContentHandler()
	 */
	abstract public <T> T sendRequest(Request<T> msg) throws IOException;
	
	/**
	 * Creates a new <code>Transport</code> of type <code>method</code> with the 
	 * provided URL over the provided proxy.
	 * 
	 * @param method the transport type.
	 * @param url the URL.
	 * @param proxy the proxy.
	 * @return a new Transport instance.
	 */
	public static Transport createTransport(Method method, URL url, Proxy proxy) {
        LOGGER.debug("Creating {} transport for {}", method, url);
		final Transport t;

		if (method.equals(Method.GET)) {
			t = new HttpGetTransport(url);
		} else {
			t = new HttpPostTransport(url);
		}
		
		return t;
	}
	
	/**
	 * Creates a new <code>Transport</code> of type <code>method</code> with the 
	 * provided URL.
	 * 
	 * @param method the transport type.
	 * @param url the url.
	 * @return a new Transport instance.
	 */
	public static Transport createTransport(Method method, URL url) {
		return createTransport(method, url, Proxy.NO_PROXY);
		
	}
	
	URL getUrl(Operation op) throws MalformedURLException {
		return new URL(url.toExternalForm() + "?operation=" + op);
	}
}
