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

import com.google.code.jscep.ScepMessage;
import com.google.code.jscep.asn1.ScepObjectIdentifiers;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

abstract class AbstractPkiRequest implements ScepRequest, Postable {
    private static final AtomicLong transCounter = new AtomicLong();
    private static final Random RANDOM = new SecureRandom();
    private static final String OPERATION = "PKIOperation";
    private final byte[] senderNonce = new byte[16];
    private final X509Certificate ca;

    public AbstractPkiRequest(X509Certificate ca) {
        this.ca = ca;
        
        RANDOM.nextBytes(senderNonce);
    }

    public final String getOperation() {
        return OPERATION;
    }

    private EnvelopedData getPkcsPkiEnvelope() {
        return new EnvelopedData(null, getRecipientInfos(), getEncryptedContentInfo(), null);
    }

    private EncryptedContentInfo getEncryptedContentInfo() {
        DERObjectIdentifier type = PKCSObjectIdentifiers.data;
        AlgorithmIdentifier rsaEncryption = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
        ASN1OctetString encryptedContent = null;
        
        return new EncryptedContentInfo(type, rsaEncryption, encryptedContent);
    }

    private ASN1Set getRecipientInfos() {
        RecipientInfo recipientInfo = null;
        
        return new DERSet(new ASN1Encodable[] {recipientInfo});        
    }

    private ContentInfo getContentInfo() {
        return new ContentInfo(PKCSObjectIdentifiers.envelopedData, getPkcsPkiEnvelope());
    }

    private ASN1Set getAuthenticatedAttributes() {
        ASN1EncodableVector attributes = new ASN1EncodableVector();

        // PKCS #10
        attributes.add(getContentTypeAttribute());
        attributes.add(getMessageDigestAttribute());

        // SCEP
        attributes.add(getTransactionIdAttribute());
        attributes.add(getMessageTypeAttribute());
        attributes.add(getSenderNonceAttribute());

        return new DERSet(attributes);
    }

    private Attribute getContentTypeAttribute() {
        return new Attribute(CMSAttributes.contentType, new DERSet());
    }

    private Attribute getMessageDigestAttribute() {
        return new Attribute(CMSAttributes.messageDigest, new DERSet());
    }

    private ASN1Set getSignerInfos() {
        SignerInfo signerInfo = new SignerInfo(null, null, getAuthenticatedAttributes(), null, null, null);
        
        return new DERSet(new ASN1Encodable[] {signerInfo});
    }

    private ASN1Set getDigestAlgorithms() {
        AlgorithmIdentifier md5 = new AlgorithmIdentifier(PKCSObjectIdentifiers.md5);

        return new DERSet(new ASN1Encodable[] {md5});
    }

    private SignedData getPkiMessage() {
        return new SignedData(getDigestAlgorithms(), getContentInfo(), null, null, getSignerInfos());
    }

    public final ScepMessage getMessage() {
        try {
            return new ScepMessage(getSignedData().getEncoded());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException(gse);
        } catch (CMSException cmse) {
            throw new RuntimeException(cmse);
        }
    }

    private CMSEnvelopedData getEnvelopedData() throws IOException, GeneralSecurityException, CMSException {
        DEREncodable content = getMessageData();
        ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.data, content);
        
        CMSProcessable messageData = new CMSProcessableByteArray(contentInfo.getDEREncoded());
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        
        return gen.generate(messageData, getCipherId(), "BC");
    }

    private CMSSignedData getSignedData() throws IOException, GeneralSecurityException, CMSException {
        CMSProcessable envelopedData = new CMSProcessableByteArray(getEnvelopedData().getEncoded());

        CMSSignedDataGenerator signer = new CMSSignedDataGenerator();

        Attribute msgType = getMessageTypeAttribute();
        Attribute transId = getTransactionIdAttribute();
        Attribute senderNonce = getSenderNonceAttribute();

        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>();
        attributes.put(msgType.getAttrType(), msgType);
        attributes.put(transId.getAttrType(), transId);
        attributes.put(senderNonce.getAttrType(), senderNonce);
        AttributeTable table = new AttributeTable(attributes);

        List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(getCaCertificate());
        CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));

        signer.addCertificatesAndCRLs(certs);
        signer.addSigner(getKeyPair().getPrivate(), getCaCertificate(), getDigestId(), table, null);

        return signer.generate(envelopedData, true, "BC");
    }

    private String getCipherId() {
        // DES
        // return SMIMECapability.dES_CBC.getId();
        // Triple-DES
        return SMIMECapability.dES_EDE3_CBC.getId();
    }

    private String getDigestId() {
        // MD5
        return CMSSignedDataGenerator.DIGEST_MD5;
        // SHA-1
        // return CMSSignedDataGenerator.DIGEST_SHA1;
        // SHA-256
        // return CMSSignedDataGenerator.DIGEST_SHA256;
        // SHA-512
        // return CMSSignedDataGenerator.DIGEST_SHA512;
    }

    private Attribute getMessageTypeAttribute() {
        return new Attribute(ScepObjectIdentifiers.messageType, new DERSet(getMessageType()));
    }

    private Attribute getTransactionIdAttribute() {
        return new Attribute(ScepObjectIdentifiers.transId, new DERSet(getTransactionId()));
    }

    private Attribute getSenderNonceAttribute() {
        return new Attribute(ScepObjectIdentifiers.senderNonce, new DERSet(getSenderNonce()));
    }

    protected DERPrintableString getTransactionId() {
        return new DERPrintableString(Long.toString(transCounter.incrementAndGet()));
    }

    protected DEROctetString getSenderNonce() {
        return new DEROctetString(senderNonce);
    }

    protected X509Certificate getCaCertificate() {
        return ca;
    }

    abstract protected KeyPair getKeyPair();
    abstract protected DERPrintableString getMessageType();
    abstract protected DEREncodable getMessageData() throws IOException, GeneralSecurityException;
}
