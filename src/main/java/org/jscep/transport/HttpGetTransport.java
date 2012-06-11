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

import org.jscep.content.ScepContentHandler;
import org.jscep.request.Operation;
import org.jscep.request.Request;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

/**
 * Transport representing the <code>HTTP GET</code> method
 *
 * @author David Grant
 */
public class HttpGetTransport extends Transport {
    private static Logger LOGGER = LoggingUtil.getLogger(HttpGetTransport.class);

    HttpGetTransport(URL url) {
        super(url);
    }

    @Override
    public <T> T sendRequest(Request msg, ScepContentHandler<T> handler) throws IOException {
        final URL url = getUrl(msg.getOperation(), msg.getMessage());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending {} to {}", msg, url);
        }
        final HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        LOGGER.debug("Received '{} {}' when sending {} to {}", new Object[]{conn.getResponseCode(), conn.getResponseMessage(), msg, url});
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException(conn.getResponseCode() + " " + conn.getResponseMessage());
        }

        return handler.getContent(conn.getInputStream(), conn.getContentType());
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
