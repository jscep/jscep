/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.content;

import com.google.code.jscep.content.CaCapabilitiesResponseHandler;
import com.google.code.jscep.content.CaCertificateResponseHandler;

import java.net.ContentHandler;
import java.net.ContentHandlerFactory;

public class ScepContentHandlerFactory implements ContentHandlerFactory {
    private static final String PKI_MESSAGE = "application/x-pki-message";
    private static final String TEXT_PLAIN = "text/plain";
    private static final String X509_CA_CERT = "application/x-x509-ca-cert";
    private static final String X509_CA_RA_CERT = "application/x-x509-ca-ra-cert";
    private static final String X509_NEXT_CA_CERT = "application/x-x509-next-ca-cert";
    
    public ContentHandler createContentHandler(String mimeType) {
        if (mimeType.equals(TEXT_PLAIN)) {
            return new CaCapabilitiesResponseHandler();
        } else if (mimeType.equals(PKI_MESSAGE)) {
            return null;
        } else if (mimeType.equals(X509_CA_CERT)) {
            return new CaCertificateResponseHandler();
        } else if (mimeType.equals(X509_CA_RA_CERT)) {
            return null;
        } else if (mimeType.equals(X509_NEXT_CA_CERT)) {
            return null;            
        } else {
            return null;
        }
    }
}
