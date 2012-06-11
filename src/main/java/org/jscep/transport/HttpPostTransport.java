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
import org.jscep.request.Postable;
import org.jscep.request.Request;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Transport representing the <code>HTTP POST</code> method
 *
 * @author David Grant
 */
public class HttpPostTransport extends Transport {
    HttpPostTransport(URL url) {
        super(url);
    }

    @Override
    public <T> T sendRequest(Request msg, ScepContentHandler<T> handler) throws IOException {
        if (!Postable.class.isAssignableFrom(msg.getClass())) {
            throw new IllegalArgumentException("POST transport may not be used for " + msg.getOperation() + " messages.");
        }

        final URL url = getUrl(msg.getOperation());
        final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        final OutputStream stream = new BufferedOutputStream(conn.getOutputStream());
        try {
            msg.write(stream);
        } finally {
            stream.close();
        }

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException(conn.getResponseCode() + " " + conn.getResponseMessage());
        }

        return handler.getContent(conn.getInputStream(), conn.getContentType());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "[POST] " + url;
    }
}
