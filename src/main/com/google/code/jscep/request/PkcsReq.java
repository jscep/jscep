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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class PkcsReq extends AbstractPkiRequest {
    private final X509Certificate cert;
    private final KeyPair pair;
    private final char[] pass;

    public PkcsReq(X509Certificate cert, KeyPair pair, char[] pass) {
        this.cert = cert;
        this.pair = pair;
        this.pass = pass;
    }

    @Override
    protected DERPrintableString getTransactionId() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(cert.getPublicKey().getEncoded());

            return new DERPrintableString(Base64.encode(digest));
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }

    @Override
    protected DERPrintableString getMessageType() {
        return new DERPrintableString("19");
    }

    @Override
    protected ContentInfo getMessageData() throws IOException, GeneralSecurityException {
        String sigAlg = "SHA1withRSA";
        PublicKey pubKey = pair.getPublic();
        X509Name subject = new X509Principal(cert.getSubjectX500Principal().getEncoded());

        // Build PKCS#10 Attributes
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        // Add the Challenge Password
        attrs.add(getPassword());
        DERSet attrSet = new DERSet(attrs);

        // Create the Certification Request
        CertificationRequest csr = new PKCS10CertificationRequest(sigAlg, subject, pubKey, attrSet, pair.getPrivate());

        return new ContentInfo(PKCSObjectIdentifiers.data, csr);
    }

    private DERSequence getPassword() {
        ASN1Encodable attrType = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
        ASN1EncodableVector attrValues = new ASN1EncodableVector();
        attrValues.add(new DERUTF8String(new String(pass)));

        ASN1EncodableVector attrVector = new ASN1EncodableVector();
        attrVector.add(attrType);
        attrVector.add(new DERSet(attrValues));

        return new DERSequence(attrVector);
    }

    @Override
    protected X509Certificate getCertificate() {
        return cert;
    }

    @Override
    protected KeyPair getKeyPair() {
        return pair;
    }
}
