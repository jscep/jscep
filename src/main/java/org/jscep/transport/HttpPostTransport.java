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

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport representing the <code>HTTP POST</code> method
 * 
 * @author David Grant
 */
@ThreadSafe
public class HttpPostTransport extends Transport {
    private static Logger LOGGER = LoggerFactory
            .getLogger(HttpPostTransport.class);

    public HttpPostTransport(URL url) {
        super(url);
    }

    @Override
    public <T> T sendRequest(Request msg, ScepResponseHandler<T> handler)
            throws TransportException {
        if (!PkiOperationRequest.class.isAssignableFrom(msg.getClass())) {
            throw new IllegalArgumentException(
                    "POST transport may not be used for " + msg.getOperation()
                            + " messages.");
        }

        URL url = getUrl(msg.getOperation());
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
        } catch (IOException e) {
            throw new TransportException(e);
        }
        conn.setDoOutput(true);

        byte[] message;
        try {
            message = Base64.decode(msg.getMessage().getBytes(Charsets.US_ASCII.name()));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        OutputStream stream = null;
        try {
            stream = new BufferedOutputStream(conn.getOutputStream());
            stream.write(message);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException e) {
                    LOGGER.error("Failed to close output stream", e);
                }
            }
        }

        try {
            int responseCode = conn.getResponseCode();
            String responseMessage = conn.getResponseMessage();

            LOGGER.debug("Received '{} {}' when sending {} to {}",
                    varargs(responseCode, responseMessage, msg, url));
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new TransportException(responseCode + " "
                        + responseMessage);
            }
        } catch (IOException e) {
            throw new TransportException("Error connecting to server.", e);
        }

        byte[] response;
        try {
            response = IOUtils.toByteArray(conn.getInputStream());
        } catch (IOException e) {
            throw new TransportException("Error reading response stream", e);
        }

        return handler.getResponse(response, conn.getContentType());
    }
}
