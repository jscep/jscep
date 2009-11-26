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

/**
 * Transport representing the <tt>HTTP POST</tt> method
 * 
 * @link http://tools.ietf.org/html/draft-nourse-scep-19#appendix-F
 */
public class HttpPostTransport extends Transport {
	private final static Logger LOGGER = Logger.getLogger(HttpPostTransport.class.getName());
	
	HttpPostTransport(URL url, Proxy proxy) {
		super(url, proxy);
	}
	
	@Override
	public <M, R> R sendMessage(Request<M, R> msg) throws IOException, MalformedURLException {
		byte[] body = (byte[]) msg.getMessage();
		
        URL url = getUrl(msg.getOperation());
        LOGGER.info("Sending Request: " + url);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.addRequestProperty("Content-Length", Integer.toString(body.length));

        OutputStream stream = conn.getOutputStream();
        stream.write(body);
        stream.close();

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        	throw new IOException(conn.getResponseCode() + " " + conn.getResponseMessage());
        }
        
        return msg.getContentHandler().getContent(conn);
	}
}
