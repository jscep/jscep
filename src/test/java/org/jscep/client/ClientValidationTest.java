package org.jscep.client;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.jscep.x509.X509Util;
import org.junit.Test;

public class ClientValidationTest {
	@Test(expected = NullPointerException.class)
	public void testNullUrl() {
		new Client(null, null, null, null);
	}
	
	@Test(expected = NullPointerException.class)
	public void testNullIdentity() {
		new Client(getUrl(), null, null, null);
	}
	
	@Test(expected = NullPointerException.class)
	public void testNullPrivateKey() {
		new Client(getUrl(), getCertificate(), null, null);
	}
	
	@Test(expected = NullPointerException.class)
	public void testNullCallbackHandler() {
		new Client(getUrl(), getCertificate(), getPrivateKey(), null);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testInvalidKeyAlgorithmPublic() {
		new Client(getUrl(), getCertificate("DSA"), getPrivateKey(), getCallbackHandler());
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testInvalidKeyAlgorithmPrivate() {
		new Client(getUrl(), getCertificate(), getPrivateKey("DSA"), getCallbackHandler());
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testInvalidUrlProtocol() {
		new Client(getUrl("ftp"), getCertificate(), getPrivateKey(), getCallbackHandler());
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testUrlWithReference() {
		new Client(getUrlWithReference(), getCertificate(), getPrivateKey(), getCallbackHandler());
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testUrlWithQueryString() {
		new Client(getUrlWithQueryString(), getCertificate(), getPrivateKey(), getCallbackHandler());
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

	private PrivateKey getPrivateKey(String algorithm) {
		return getKeyPair(algorithm).getPrivate();
	}

	private X509Certificate getCertificate(String algorithm) {
		try {
			return X509Util.createEphemeralCertificate(getSubject(), getKeyPair(algorithm));
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	private KeyPair getKeyPair(String algorithm) {
		try {
			return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private CallbackHandler getCallbackHandler() {
		return new NoSecurityCallbackHandler();
	}

	private PrivateKey getPrivateKey() {
		return getPrivateKey("RSA");
	}

	private X509Certificate getCertificate() {
		return getCertificate("RSA");
	}

	private X500Principal getSubject() {
		return new X500Principal("CN=jscep");
	}

	private URL getUrl() {
		return getUrl("http");
	}
}
