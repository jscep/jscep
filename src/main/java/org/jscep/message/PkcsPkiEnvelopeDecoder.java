/*
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.message;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PkcsPkiEnvelopeDecoder {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(PkcsPkiEnvelopeDecoder.class);
    private final X509Certificate recipient;
    private final PrivateKey priKey;

    /**
     * 
     * @param recipient the entity for whom the message was enveloped
     * @param priKey the key to open decrypt the envelope
     */
    public PkcsPkiEnvelopeDecoder(X509Certificate recipient, PrivateKey priKey) {
        this.recipient = recipient;
        this.priKey = priKey;
    }

    public byte[] decode(CMSEnvelopedData ed) throws IOException {
        LOGGER.debug("Decrypting message: {}", ed.getEncoded());

        final RecipientInformationStore recipientInfos = ed.getRecipientInfos();
        RecipientInformation info =  recipientInfos.get(new JceKeyTransRecipientId(recipient));
        
        if (info == null) {
            throw new IOException("Missing expected key transfer recipient");
        }
        
        try {
            return info.getContent(new JceKeyTransEnvelopedRecipient(priKey));
        } catch (CMSException e) {
            IOException ioe = new IOException();
          ioe.initCause(e);

          throw ioe;
        }
    }
}
