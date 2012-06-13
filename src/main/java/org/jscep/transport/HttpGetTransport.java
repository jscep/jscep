/*
 * Copyright (c) 2009-2012 David Grant
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import org.jscep.content.InvalidContentException;
import org.jscep.content.InvalidContentTypeException;
import org.jscep.content.ScepContentHandler;
import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.ByteStreams;

/**
 * Transport representing the <code>HTTP GET</code> method
 *
 * @author David Grant
 */
public class HttpGetTransport extends Transport {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpGetTransport.class);

    HttpGetTransport(URL url) {
        super(url);
    }

    @Override
    public <T> T sendRequest(Request msg, ScepContentHandler<T> handler) throws TransportException, InvalidContentTypeException, InvalidContentException {
        URL url;
		try {
			url = getUrl(msg.getOperation(), msg.getMessage());
		} catch (MalformedURLException e) {
			throw new TransportException(e);
		} catch (UnsupportedEncodingException e) {
			throw new TransportException(e);
		}
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending {} to {}", msg, url);
        }
        HttpURLConnection conn;
		try {
			conn = (HttpURLConnection) url.openConnection();
		} catch (IOException e) {
			throw new TransportException(e);
		}

		try {
	        int responseCode = conn.getResponseCode();
			String responseMessage = conn.getResponseMessage();
			
			LOGGER.debug("Received '{} {}' when sending {} to {}", new Object[]{responseCode, responseMessage, msg, url});
	        if (responseCode != HttpURLConnection.HTTP_OK) {
	            throw new TransportException(responseCode + " " + responseMessage);
	        }
		} catch (IOException e) {
			throw new TransportException(e);
		}
        
        byte[] response;
        try {
			 response = ByteStreams.toByteArray(conn.getInputStream());
		} catch (IOException e) {
			throw new TransportException("Error reading response stream", e);
		}

        return handler.getContent(response, conn.getContentType());
    }

    private URL getUrl(Operation op, String message) throws MalformedURLException, UnsupportedEncodingException {
        return new URL(getUrl(op).toExternalForm() + "&message=" + URLEncoder.encode(message, "UTF-8"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "[GET] " + url;
    }
}
