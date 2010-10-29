/*
 * Copyright (c) 2009-2010 David Grant
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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.logging.Logger;

import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.jscep.util.LoggingUtil;


/**
 * Transport representing the <code>HTTP GET</code> method
 * 
 * @author David Grant
 */
public class HttpGetTransport extends Transport {
	private static Logger LOGGER = LoggingUtil.getLogger(HttpGetTransport.class);

	HttpGetTransport(URL url, Proxy proxy) {
		super(url, proxy);
	}

	@Override
	public <T> T sendMessage(Request<T> msg) throws IOException {
		LOGGER.entering(getClass().getName(), "sendMessage", msg);
		
		final URL url = getUrl(msg.getOperation(), msg.getMessage());
		System.out.println(url);
		final HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);

		if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
			IOException ioe = new IOException(conn.getResponseCode() + " " + conn.getResponseMessage());
			
			LOGGER.throwing(getClass().getName(), "sendMessage", ioe);
			throw ioe;
		}

		final T response = msg.getContentHandler().getContent(conn.getInputStream(), conn.getContentType());
		
		LOGGER.exiting(getClass().getName(), "sendMessage", response);
		return response;
	}

	private URL getUrl(Operation op, String message) throws MalformedURLException {
		return new URL(getUrl(op).toExternalForm() + "&message=" + message);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		if (proxy == Proxy.NO_PROXY) {
			return "HTTP GET Transport for " + url;
		} else {
			return "HTTP GET Transport for " + url + " (using " + proxy + ")";
		}
	}
}
