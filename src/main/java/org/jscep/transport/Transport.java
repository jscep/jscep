package org.jscep.transport;

import java.net.MalformedURLException;
import java.net.URL;

import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

/**
 * This class represents an abstract transport method for sending a message to a
 * SCEP server.
 */
public abstract class Transport {
    private final URL url;

    /**
     * Creates a new <tt>Transport</tt> for the given URL.
     * 
     * @param url
     *            the <tt>URL</tt> used for sending requests.
     */
    Transport(URL url) {
	this.url = url;
    }

    /**
     * Sends the provided request to the <tt>URL</tt> provided in the
     * constructor.
     * <p>
     * This method will use the provided <tt>ScepResponseHandler</tt> to parse
     * the SCEP server response. If the response can be correctly parsed, this
     * method will return the response. Otherwise, this method will throw a
     * <tt>TransportException</tt>
     * 
     * @param <T>
     *            the response type.
     * @param msg
     *            the message to send.
     * @param handler
     *            the handler used to parse the response.
     * @return the SCEP server response.
     * @throws TransportException
     *             if any transport error occurs.
     */
    public abstract <T> T sendRequest(Request msg,
	    ScepResponseHandler<T> handler) throws TransportException;

    /**
     * Returns the <tt>URL</tt> for the given operation.
     * 
     * @param op
     *            the operation.
     * @return the <tt>URL</tt> for the given operation.
     * @throws TransportException
     *             if the generated <tt>URL</tt> is malformed.
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
