package com.google.code.jscep.content;

import java.io.IOException;
import java.net.ContentHandler;
import java.net.URLConnection;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

public class CertRepResponseHandler extends ContentHandler {
    @Override
    public Object getContent(URLConnection conn) throws IOException {
        try {
            return new CMSSignedData(conn.getInputStream());
        } catch (CMSException ce) {
            throw new IOException(ce);
        }
    }
}
