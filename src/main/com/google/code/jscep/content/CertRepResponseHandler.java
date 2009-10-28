package com.google.code.jscep.content;

import com.google.code.jscep.response.CertRep;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.ContentHandler;
import java.net.URLConnection;

public class CertRepResponseHandler extends ContentHandler {
    @Override
    public Object getContent(URLConnection urlConnection) throws IOException {
        try {
            InputStream stream = urlConnection.getInputStream();
            CMSSignedDataParser parser = new CMSSignedDataParser(stream);
            
            return new CertRep(parser);
        } catch (CMSException ce) {
            throw new IOException(ce);
        }
    }
}
