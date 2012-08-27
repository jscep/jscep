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
 */
@ThreadSafe
public final class HttpPostTransport extends Transport {
    private static final Logger LOGGER = LoggerFactory
	    .getLogger(HttpPostTransport.class);

    /**
     * Creates a new <tt>HttpPostTransport</tt> for the given <tt>URL</tt>.
     * 
     * @param url the <tt>URL</tt> to send <tt>POST</tt> requests to.
     */
    public HttpPostTransport(URL url) {
	super(url);
    }

    /**
     * {@inheritDoc}
     */
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
	    message = Base64.decode(msg.getMessage().getBytes(
		    Charsets.US_ASCII.name()));
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
