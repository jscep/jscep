/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.content;

import com.google.code.jscep.response.CaCertificateResponse;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.IOException;
import java.net.ContentHandler;
import java.net.URLConnection;

public class CaCertificateResponseHandler extends ContentHandler {
    public CaCertificateResponse getContent(URLConnection conn) throws IOException {
        try {
            X509Certificate cert = X509Certificate.getInstance(conn.getInputStream());

            return new CaCertificateResponse(cert);
        } catch (CertificateException ce) {
            throw new IOException(ce);
        }
    }
}
