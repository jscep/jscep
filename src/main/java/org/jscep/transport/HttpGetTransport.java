package org.jscep.transport;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import net.jcip.annotations.ThreadSafe;

import org.apache.commons.io.IOUtils;
import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport representing the <code>HTTP GET</code> method
 */
@ThreadSafe
public final class HttpGetTransport extends Transport {
    private static final Logger LOGGER = LoggerFactory
	    .getLogger(HttpGetTransport.class);

    /**
     * Creates a new <tt>HttpGetTransport</tt> for the given <tt>URL</tt>.
     * 
     * @param url the <tt>URL</tt> to send <tt>GET</tt> requests to.
     */
    public HttpGetTransport(URL url) {
	super(url);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T sendRequest(Request msg, ScepResponseHandler<T> handler)
	    throws TransportException {
	URL url = getUrl(msg.getOperation(), msg.getMessage());
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

	    LOGGER.debug("Received '{} {}' when sending {} to {}",
		    varargs(responseCode, responseMessage, msg, url));
	    if (responseCode != HttpURLConnection.HTTP_OK) {
		throw new TransportException(responseCode + " "
			+ responseMessage);
	    }
	} catch (IOException e) {
	    throw new TransportException("Error connecting to server", e);
	}

	byte[] response;
	try {
	    response = IOUtils.toByteArray(conn.getInputStream());
	} catch (IOException e) {
	    throw new TransportException("Error reading response stream", e);
	}

	return handler.getResponse(response, conn.getContentType());
    }

    private URL getUrl(Operation op, String message) throws TransportException {
	try {
	    return new URL(getUrl(op).toExternalForm() + "&message="
		    + URLEncoder.encode(message, "UTF-8"));
	} catch (MalformedURLException e) {
	    throw new TransportException(e);
	} catch (UnsupportedEncodingException e) {
	    throw new TransportException(e);
	}
    }
}
