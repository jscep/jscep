/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.response;

import javax.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 23-Oct-2009
 * Time: 16:41:48
 * To change this template use File | Settings | File Templates.
 */
public class CaCertificateResponse implements ScepResponse {
    private final X509Certificate ca;
    private final X509Certificate ra;
    
    public CaCertificateResponse(X509Certificate ca) {
        this(ca, null);
    }

    public CaCertificateResponse(X509Certificate ca, X509Certificate ra) {
        this.ca = ca;
        this.ra = ra;
    }

    public X509Certificate getCaCertificate() {
        return ca;
    }

    public X509Certificate getRaCertificate() {
        return ra;
    }

    public boolean hasRaCertificate() {
        return ra != null;
    }
}
