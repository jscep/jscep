package org.jscep.transport;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.apache.commons.io.IOUtils;
import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIHostName;

/**
 * AbstractTransport representing the <code>HTTP GET</code> method
 */
@ThreadSafe
final class UrlConnectionGetTransport extends AbstractTransport {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(UrlConnectionGetTransport.class);

    private SSLSocketFactory sslSocketFactory;

    /**
     * Creates a new <tt>HttpGetTransport</tt> for the given <tt>URL</tt>.
     *
     * @param url
     *            the <tt>URL</tt> to send <tt>GET</tt> requests to.
     */
    public UrlConnectionGetTransport(final URL url) {
        this(url, (SSLSocketFactory)SSLSocketFactory.getDefault());
    }

    /**
     * Creates a new <tt>HttpGetTransport</tt> for the given <tt>URL</tt>.
     *
     * @param url
     *            the <tt>URL</tt> to send <tt>GET</tt> requests to.
     * @param sslSocketFactory
     *            the sslSocketFactory to be passed along https requests
     */
    public UrlConnectionGetTransport(final URL url, final SSLSocketFactory sslSocketFactory) {
        super(url);

        SSLParameters sslParameters = new SSLParameters();
        List<SNIServerName> sniServerNames = new ArrayList<SNIServerName>(1);
        sniServerNames.add(new SNIHostName(url.getHost()));
        sslParameters.setServerNames(sniServerNames);

        this.sslSocketFactory = new ParameterizedSSLSocketFactory(sslSocketFactory, sslParameters);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T sendRequest(final Request msg,
            final ScepResponseHandler<T> handler) throws TransportException {

        URL url = getUrl(msg.getOperation(), msg.getMessage());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending {} to {}", msg, url);
        }
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
            if(conn instanceof HttpsURLConnection && sslSocketFactory != null){
                ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
            }
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

    private URL getUrl(final Operation op, final String message)
            throws TransportException {
        try {
            return new URL(getUrl(op).toExternalForm() + "&message="
                    + URLEncoder.encode(message, "UTF-8"));
        } catch (MalformedURLException e) {
            throw new TransportException(e);
        } catch (UnsupportedEncodingException e) {
            throw new TransportException(e);
        }
    }

    public SSLSocketFactory getSslSocketFactory() {
        return sslSocketFactory;
    }
}
