/*
 * Copyright (c) 2009 David Grant
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

package com.google.code.jscep;

import java.net.Proxy;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

public class ClientConfiguration {
	private URL url;
	private Proxy proxy;
	private String caId;
	private KeyPair keyPair;
	private X509Certificate identity;
	private X509Certificate ca;
	private X500Principal subject;
	private byte[] caDigest;
	private String digestAlgorithm;
	
	public void setUrl(URL url) {
		this.url = url;
	}
	
	public URL getUrl() {
		return url;
	}
	
	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}
	
	public Proxy getProxy() {
		return proxy;
	}
	
	public void setCaIdentifier(String caId) {
		this.caId = caId;
	}
	
	public String getCaIdentifier() {
		return caId;
	}
	
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public KeyPair getKeyPair() {
		return keyPair;
	}
	
	public void setSubject(X500Principal subject) {
		this.subject = subject;
	}
	
	public X500Principal getSubject() {
		return subject;
	}
	
	public void setIdentity(X509Certificate identity) {
		this.identity = identity;
	}
	
	public X509Certificate getIdentity() {
		return identity;
	}
	
	/**
	 * The message digest of the CA certificate.
	 * 
	 * @param caDigest the digest.
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
	 */
	public void setCaDigest(byte[] caDigest) {
		this.caDigest = caDigest;
	}
	
	public byte[] getCaDigest() {
		return caDigest;
	}
	
	public void setCaCertificate(X509Certificate ca) {
		this.ca = ca;
	}
	
	public X509Certificate getCaCertificate() {
		return ca;
	}
	
	/**
	 * One of <tt>MD5</tt>, <tt>SHA-1</tt>, <tt>SHA-256</tt> or <tt>SHA-512</tt>.  Defaults to MD5.
	 * 
	 * @param digestAlgorithm the hash algorithm for encoding the certificate.
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-2.1.2.1
	 */
	public void setDigestAlgorithm(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}
	
	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}
}
