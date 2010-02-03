/*
 * Copyright (c) 2009-2010 David Grant
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

package com.google.code.jscep.client;

import java.net.Proxy;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import com.google.code.jscep.util.HexUtil;

/**
 * This class represents the various configuration options that can be used to 
 * alter the behaviour of the client.
 */
public class ClientConfiguration {
	private final URL url;
	private final Proxy proxy;
	private String caId;
	private KeyPair keyPair;
	private X509Certificate identity;
	private X509Certificate ca;
	private X500Principal subject;
	private byte[] caDigest;
	private String digestAlgorithm;
	
	/**
	 * Creates a new instance of this class with the given SCEP URL.
	 * 
	 * @param url the URL of the SCEP server.
	 */
	public ClientConfiguration(URL url) {
		this.url = url;
		this.proxy = Proxy.NO_PROXY;
	}
	
	/**
	 * Creates a new instance of this class with the given SCEP URL, and the proxy
	 * needed to access that URL.
	 * 
	 * @param url the URL of the SCEP server.
	 * @param proxy the proxy to use to access the SCEP server.
	 */
	public ClientConfiguration(URL url, Proxy proxy) {
		this.url = url;
		this.proxy = proxy;
	}
	
	/**
	 * Returns the URL of the SCEP server.
	 * 
	 * @return the URL of the SCEP server.
	 */
	public URL getUrl() {
		return url;
	}
	
	/**
	 * Returns the proxy to use to access the SCEP server.
	 * 
	 * @return the proxy.
	 */
	public Proxy getProxy() {
		return proxy;
	}
	
	/**
	 * Sets the CA identification string.
	 * 
	 * @param caIdentifier the CA identification string.
	 */
	public void setCaIdentifier(String caIdentifier) {
		this.caId = caIdentifier;
	}
	
	/**
	 * Returns the CA identification string.
	 * 
	 * @return the CA identification string.
	 */
	public String getCaIdentifier() {
		return caId;
	}
	
	/**
	 * Sets the key pair to use for certification.
	 * 
	 * @param keyPair the key pair.
	 */
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	/**
	 * Returns the key pair to use for certification.
	 * 
	 * @return the key pair.
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}
	
	/**
	 * Sets the certification subject.
	 * 
	 * @param subject the certification subject.
	 */
	public void setSubject(X500Principal subject) {
		this.subject = subject;
	}
	
	/**
	 * Returns the certification subject.
	 * 
	 * @return the certification subject.
	 */
	public X500Principal getSubject() {
		return subject;
	}
	
	/**
	 * Sets the certification identity.
	 * 
	 * @param identity the certification identity.
	 */
	public void setIdentity(X509Certificate identity) {
		this.identity = identity;
	}
	
	/**
	 * Returns the certification identity.
	 * 
	 * @return the certification identity.
	 */
	public X509Certificate getIdentity() {
		return identity;
	}
	
	/**
	 * Set the message digest of the CA certificate.
	 * <p>
	 * The digestAlgorithm must be one of <tt>MD5</tt>, <tt>SHA-1</tt>, 
	 * <tt>SHA-256</tt> or <tt>SHA-512</tt>
	 * 
	 * @param caDigest the digest.
	 * @param digestAlgorithm the digest algorithm.
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
	 */
	public void setCaDigest(byte[] caDigest, String digestAlgorithm) {
		this.caDigest = caDigest;
		this.digestAlgorithm = digestAlgorithm;
	}
	
	/**
	 * Set the MD5 message digest of the CA certificate.
	 * 
	 * @param caDigest the digest.
	 */
	public void setCaDigest(byte[] caDigest) {
		this.caDigest = caDigest;
		this.digestAlgorithm = "MD5";
	}
	
	/**
	 * Set the message digest of the CA certificate.
	 * <p>
	 * The digestAlgorithm must be one of <tt>MD5</tt>, <tt>SHA-1</tt>, 
	 * <tt>SHA-256</tt> or <tt>SHA-512</tt>
	 * 
	 * @param caDigest the digest in hex format.
	 * @param digestAlgorithm the digest algorithm.
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
	 */
	public void setCaDigest(String caDigest, String digestAlgorithm) {
		this.caDigest = HexUtil.fromHex(caDigest);
		this.digestAlgorithm = digestAlgorithm;
	}
	
	/**
	 * Set the MD5 message digest of the CA certificate.
	 * 
	 * @param caDigest the digest in hex format.
	 */
	public void setCaDigest(String caDigest) {
		this.caDigest = HexUtil.fromHex(caDigest);
		this.digestAlgorithm = "MD5";
	}
	
	/**
	 * Returns the CA message digest.
	 * 
	 * @return the CA message digest.
	 */
	public byte[] getCaDigest() {
		return caDigest;
	}
	
	/**
	 * Sets the CA certificate.
	 * 
	 * @param ca the CA certificate.
	 */
	public void setCaCertificate(X509Certificate ca) {
		this.ca = ca;
	}
	
	/**
	 * Returns the CA certificate.
	 * 
	 * @return the CA certificate.
	 */
	public X509Certificate getCaCertificate() {
		return ca;
	}

	/**
	 * Returns the digest algorithm.
	 * 
	 * @return the digest algorithm.
	 */
	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}
}
