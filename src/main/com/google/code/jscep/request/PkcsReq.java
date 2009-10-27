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
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;

public class PkcsReq extends AbstractPkiRequest {
    private final X500Principal subject;
    private final KeyPair pair;
    private final char[] pass;

    public PkcsReq(X509Certificate ca, X500Principal subject, KeyPair pair, char[] pass) {
        super(ca);
        
        this.subject = subject;
        this.pair = pair;
        this.pass = pass;
    }

    @Override
    protected DERPrintableString getTransactionId() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(pair.getPublic().getEncoded());

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
        CertificationRequestInfo reqInfo = getRequestInfo();
        DERBitString signature = signRequestInfo(reqInfo);

        CertificationRequest pkcs10 = new CertificationRequest(reqInfo, getDigestAlgorithm(), signature);

        return new ContentInfo(PKCSObjectIdentifiers.data, pkcs10);
    }

    private DERBitString signRequestInfo(CertificationRequestInfo reqInfo) throws IOException, GeneralSecurityException {
        Signature sig = Signature.getInstance(getDigestAlgorithm().getObjectId().getId());
        sig.initSign(pair.getPrivate());
        sig.update(reqInfo.getEncoded());

        return new DERBitString(sig.sign());
    }

    private CertificationRequestInfo getRequestInfo() throws IOException {
        X509Name subjName = new X509Principal(subject.getEncoded());
        // Build PKCS#10 Attributes
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(getPassword());
        DERSet attributeSet = new DERSet(attributes);

        return new CertificationRequestInfo(subjName, getSubjectPublicKeyInfo(), attributeSet);
    }

    public X500Principal getSubject() {
        return subject;
    }

    private SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return new SubjectPublicKeyInfo(getPublicKeyAlgorithm(), pair.getPublic().getEncoded());
    }

    private AlgorithmIdentifier getPublicKeyAlgorithm() {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
    }

    private AlgorithmIdentifier getDigestAlgorithm() {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption);
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
        return null;
    }

    @Override
    protected KeyPair getKeyPair() {
        return pair;
    }
}
