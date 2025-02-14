package org.jscep.client;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.security.auth.callback.CallbackHandler;

import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.junit.Test;

public class ClientValidationTest {
    @Test(expected = NullPointerException.class)
    public void testNullUrl() {
        new Client(null, (CallbackHandler) null);
    }

    @Test(expected = NullPointerException.class)
    public void testNullCallbackHandler() throws URISyntaxException {
        new Client(getUrl(), (CallbackHandler) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidUrlProtocol() throws URISyntaxException {
        new Client(getUrl("ftp"), getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithReference() throws URISyntaxException {
        new Client(getUrlWithReference(), getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithQueryString() throws URISyntaxException {
        new Client(getUrlWithQueryString(), getCallbackHandler());
    }

    private URL getUrlWithQueryString() throws URISyntaxException {
        try {
            return new URI("http://jscep.org/pkiclient.exe?key=value").toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private URL getUrlWithReference() throws URISyntaxException {
        try {
            return new URI("http://jscep.org/pkiclient.exe#reference").toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private URL getUrl(String protocol) throws URISyntaxException {
        try {
            return new URI(protocol, "jscep.org", "/pkiclient.exe", null).toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private CallbackHandler getCallbackHandler() {
        return new DefaultCallbackHandler(new OptimisticCertificateVerifier());
    }

    private URL getUrl() throws URISyntaxException {
        return getUrl("http");
    }
}
