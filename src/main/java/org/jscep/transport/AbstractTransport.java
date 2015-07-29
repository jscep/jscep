package org.jscep.transport;

import java.net.MalformedURLException;
import java.net.URL;

import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;

import javax.net.ssl.SSLSocketFactory;

/**
 * This class represents an abstract transport method for sending a message to a
 * SCEP server.
 */
public abstract class AbstractTransport implements Transport {
    private final URL url;

    /**
     * Creates a new <tt>AbstractTransport</tt> for the given URL.
     * 
     * @param url
     *            the <tt>URL</tt> used for sending requests.
     */
    public AbstractTransport(final URL url) {
        this.url = url;
    }

    /**
     * Returns the <tt>URL</tt> for the given operation.
     * 
     * @param op
     *            the operation.
     * @return the <tt>URL</tt> for the given operation.
     * @throws TransportException
     *             if the generated <tt>URL</tt> is malformed.
     */
    public final URL getUrl(final Operation op) throws TransportException {
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
