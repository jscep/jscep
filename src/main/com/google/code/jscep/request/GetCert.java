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

package com.google.code.jscep.request;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class GetCert extends AbstractPkiRequest {
    private final X500Principal issuer;
    private final BigInteger serial;

    public GetCert(X509Certificate ca, X500Principal issuer, BigInteger serial) {
        super(ca);
        
        this.issuer = issuer;
        this.serial = serial;
    }

    @Override
    protected DERPrintableString getMessageType() {
        return new DERPrintableString("21");
    }

    @Override
    protected ContentInfo getMessageData() throws IOException {
        X509Name issuerName = new X509Principal(issuer.getEncoded());
        IssuerAndSerialNumber isn = new IssuerAndSerialNumber(issuerName, serial);

        return new ContentInfo(PKCSObjectIdentifiers.data, isn);
    }

    @Override
    protected X509Certificate getCertificate() {
        return null;
    }

    @Override
    protected KeyPair getKeyPair() {
        return null;
    }
}
