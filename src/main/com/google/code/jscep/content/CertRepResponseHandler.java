package com.google.code.jscep.content;

import com.google.code.jscep.response.CertRep;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformationStore;

import java.io.IOException;
import java.io.InputStream;
import java.net.ContentHandler;
import java.net.URLConnection;

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
