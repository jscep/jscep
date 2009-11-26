package com.google.code.jscep.content;

import java.io.IOException;
import java.net.URLConnection;

public abstract class ScepContentHandler<T> {
	/**
	 * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.2.1
	 */
	protected static final String PKI_MESSAGE = "application/x-pki-message";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#appendix-D.2
     */
	protected static final String TEXT_PLAIN = "text/plain";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.1
     */
    protected static final String X509_CA_CERT = "application/x-x509-ca-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.1.1.2
     */
    protected static final String X509_CA_RA_CERT = "application/x-x509-ca-ra-cert";
    /**
     * @link http://tools.ietf.org/html/draft-nourse-scep-19#section-5.2.6.1
     */
    protected static final String X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
    
	public boolean isType(URLConnection conn, String mimeType) {
		return conn.getContentType().equals(mimeType);
	}
	
	abstract public T getContent(URLConnection connection) throws IOException;
}
