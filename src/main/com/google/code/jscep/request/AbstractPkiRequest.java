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

import com.google.code.jscep.SCEPObjectIdentifiers;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.smime.SMIMECapability;
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

    public AbstractPkiRequest() {
        RANDOM.nextBytes(senderNonce);
    }

    public final String getOperation() {
        return OPERATION;
    }

    public final Object getMessage() {
        // DES
//        DERObjectIdentifier algOid = SMIMECapability.dES_CBC;
        // Triple-DES
        DERObjectIdentifier algOid = SMIMECapability.dES_EDE3_CBC;
        // MD5
        String hashOid = CMSSignedDataGenerator.DIGEST_MD5;
        // SHA-1
//        String hashOid = CMSSignedDataGenerator.DIGEST_SHA1;
        // SHA-256
//        String hashOid = CMSSignedDataGenerator.DIGEST_SHA256;
        // SHA-512
//        String hashOid = CMSSignedDataGenerator.DIGEST_SHA512;

        try {
            byte[] messageData = getMessageData().getDEREncoded();
            CMSProcessable envelopable = new CMSProcessableByteArray(messageData);
            CMSEnvelopedDataGenerator enGenerator = new CMSEnvelopedDataGenerator();
            CMSEnvelopedData env = enGenerator.generate(envelopable, algOid.getId(), "BC");
            CMSProcessable signable = new CMSProcessableByteArray(env.getEncoded());

            CMSSignedDataGenerator signer = new CMSSignedDataGenerator();

            Attribute msgType = getMessageTypeAttribute();
            Attribute transId = getTransactionIdAttribute();
            Attribute senderNonce = getSenderNonceAttribute();

            Hashtable<DERObjectIdentifier, Attribute> attrs = new Hashtable<DERObjectIdentifier, Attribute>();
            attrs.put(msgType.getAttrType(), msgType);
            attrs.put(transId.getAttrType(), transId);
            attrs.put(senderNonce.getAttrType(), senderNonce);
            AttributeTable table = new AttributeTable(attrs);

            List<X509Certificate> certList = new ArrayList<X509Certificate>(1);
            certList.add(getCertificate());
            CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));

            signer.addCertificatesAndCRLs(certs);
            signer.addSigner(getKeyPair().getPrivate(), getCertificate(), hashOid, table, null);

            return signer.generate(signable, true, "BC").getEncoded();

        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException(gse);
        } catch (CMSException cmse) {
            throw new RuntimeException(cmse);
        }
    }

    private Attribute getMessageTypeAttribute() {
        return new Attribute(SCEPObjectIdentifiers.messageType, new DERSet(getMessageType()));
    }

    private Attribute getTransactionIdAttribute() {
        return new Attribute(SCEPObjectIdentifiers.transId, new DERSet(getTransactionId()));
    }

    private Attribute getSenderNonceAttribute() {
        return new Attribute(SCEPObjectIdentifiers.senderNonce, new DERSet(getSenderNonce()));
    }

    protected DERPrintableString getTransactionId() {
        return new DERPrintableString(Long.toString(transCounter.incrementAndGet()));
    }

    protected DEROctetString getSenderNonce() {
        return new DEROctetString(senderNonce);
    }

    abstract protected KeyPair getKeyPair();
    abstract protected X509Certificate getCertificate();
    abstract protected DERPrintableString getMessageType();
    abstract protected ContentInfo getMessageData() throws IOException, GeneralSecurityException;
}
