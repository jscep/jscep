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

import java.net.MalformedURLException;
import java.net.URL;

import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

/**
 * This class represents a transport for sending a message to the SCEP server.
 * <p/>
 * Example usage:
 * 
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
    private final URL url;

    Transport(URL url) {
	this.url = url;
    }

    /**
     * Returns the URL configured for use by this transport.
     * 
     * @return the URL.
     */
    public final URL getUrl() {
	return url;
    }

    /**
     * Sends the given request to the URL provided in the constructor and uses
     * the {@link Request}'s content handler to parse the response.
     * 
     * @param <T>
     *            the response type.
     * @param msg
     *            the message to send.
     * @param handler
     *            the response handler
     * @return the response of type T.
     * @throws TransportException
     * @throws InvalidContentTypeException
     * @throws InvalidContentException
     */
    public abstract <T> T sendRequest(Request msg,
	    ScepResponseHandler<T> handler) throws TransportException;

    /**
     * Returns the URL for the given operation.
     * 
     * @param op
     *            the operation.
     * @return the URL for the given operation.
     * @throws TransportException
     *             if the generated URL is malformed.
     */
    final URL getUrl(final Operation op) throws TransportException {
	try {
	    return new URL(url.toExternalForm() + "?operation=" + op.getName());
	} catch (MalformedURLException e) {
	    throw new TransportException(e);
	}
    }

    /**
     * Converts the given object varargs to an object array.
     * 
     * @param objects
     *            the objects to convert.
     * @return the object array.
     */
    protected final Object[] varargs(final Object... objects) {
	return objects;
    }
}
