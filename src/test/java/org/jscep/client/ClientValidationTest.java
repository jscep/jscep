package org.jscep.client;

import java.net.MalformedURLException;
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
    public void testNullCallbackHandler() {
	new Client(getUrl(), (CallbackHandler) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidUrlProtocol() {
	new Client(getUrl("ftp"), getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithReference() {
	new Client(getUrlWithReference(), getCallbackHandler());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUrlWithQueryString() {
	new Client(getUrlWithQueryString(), getCallbackHandler());
    }

    private URL getUrlWithQueryString() {
	try {
	    return new URL("http://jscep.org/pkiclient.exe?key=value");
	} catch (MalformedURLException e) {
	    throw new RuntimeException(e);
	}
    }

    private URL getUrlWithReference() {
	try {
	    return new URL("http://jscep.org/pkiclient.exe#reference");
	} catch (MalformedURLException e) {
	    throw new RuntimeException(e);
	}
    }

    private URL getUrl(String protocol) {
	try {
	    return new URL(protocol, "jscep.org", "pkiclient.exe");
	} catch (MalformedURLException e) {
	    throw new RuntimeException(e);
	}
    }

    private CallbackHandler getCallbackHandler() {
	return new DefaultCallbackHandler(new OptimisticCertificateVerifier());
    }

    private URL getUrl() {
	return getUrl("http");
    }
}
