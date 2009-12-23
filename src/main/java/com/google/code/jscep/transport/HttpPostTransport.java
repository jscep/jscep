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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.logging.Logger;

import com.google.code.jscep.request.Request;
import com.google.code.jscep.util.LoggingUtil;

/**
 * Transport representing the <tt>HTTP POST</tt> method
 * 
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#appendix-F
 */
public class HttpPostTransport extends Transport {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.transport");
	
	HttpPostTransport(URL url, Proxy proxy) {
		super(url, proxy);
	}
	
	@Override
	public <T> T sendMessage(Request<T> msg) throws IOException, MalformedURLException {
		LOGGER.entering(getClass().getName(), "sendMessage");
		
		final byte[] body = (byte[]) msg.getMessage();
        final URL url = getUrl(msg.getOperation());
        final HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.addRequestProperty("Content-Length", Integer.toString(body.length));

        final OutputStream stream = conn.getOutputStream();
        stream.write(body);
        stream.close();

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        	IOException ioe = new IOException(conn.getResponseCode() + " " + conn.getResponseMessage());
        	
        	LOGGER.throwing(getClass().getName(), "sendMessage", ioe);
        	throw ioe;
        }
        
        T response  = msg.getContentHandler().getContent(conn.getInputStream(), conn.getContentType());
        
        LOGGER.exiting(getClass().getName(), "sendMessage", response);
        return response;
	}
	
	@Override
	public String toString() {
		if (proxy == Proxy.NO_PROXY) {
			return "HTTP POST Transport for " + url;
		} else {
			return "HTTP POST Transport for " + url + " (using " + proxy + ")";
		}
	}
}
