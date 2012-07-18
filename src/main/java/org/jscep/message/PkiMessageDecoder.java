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
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.asn1.ScepObjectIdentifiers;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PkiMessageDecoder {
    private static Logger LOGGER = LoggerFactory
            .getLogger(PkiMessageDecoder.class);
    private final PkcsPkiEnvelopeDecoder decoder;

    public PkiMessageDecoder(PkcsPkiEnvelopeDecoder decoder) {
        this.decoder = decoder;
    }

    @SuppressWarnings("unchecked")
    public PkiMessage<?> decode(byte[] bytes) throws IOException {
        CMSSignedData signedData;
        try {
            signedData = new CMSSignedData(bytes);
        } catch (CMSException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        LOGGER.debug("Decoding message: {}", signedData.getEncoded());
        // The signed content is always an octet string
        CMSProcessable signedContent = signedData.getSignedContent();

        Store store;
        try {
            store = signedData.getCertificates();
        } catch (Exception e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        Collection<SignerInformation> signerInfos = signedData.getSignerInfos()
                .getSigners();
        SignerInformation signerInfo = signerInfos.iterator().next();
        Collection<?> certColl;
        try {
            certColl = store.getMatches(signerInfo.getSID());
        } catch (Exception e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        if (certColl.size() > 0) {
            X509CertificateHolder cert = (X509CertificateHolder) certColl
                    .iterator().next();
            LOGGER.debug("Verifying message using key belonging to '{}'",
                    cert.getSubject());
            SignerInformationVerifier verifier;
            try {
                verifier = new JcaSimpleSignerInfoVerifierBuilder().build(cert);
            } catch (OperatorCreationException e) {
                IOException ioe = new IOException();
                ioe.initCause(e);

                throw ioe;
            } catch (CertificateException e) {
                IOException ioe = new IOException();
                ioe.initCause(e);

                throw ioe;
            }

            try {
                signerInfo.verify(verifier);
            } catch (Exception e) {
                IOException ioe = new IOException();
                ioe.initCause(e);

                throw ioe;
            }
        } else {
            LOGGER.error("Unable to verify message");
        }

        Hashtable<DERObjectIdentifier, Attribute> attrTable = signerInfo
                .getSignedAttributes().toHashtable();

        MessageType messageType = toMessageType(attrTable
                .get(toOid(ScepObjectIdentifiers.MESSAGE_TYPE)));
        Nonce senderNonce = toNonce(attrTable
                .get(toOid(ScepObjectIdentifiers.SENDER_NONCE)));
        TransactionId transId = toTransactionId(attrTable
                .get(toOid(ScepObjectIdentifiers.TRANS_ID)));

        PkiMessage<?> decoded;
        if (messageType == MessageType.CERT_REP) {
            PkiStatus pkiStatus = toPkiStatus(attrTable
                    .get(toOid(ScepObjectIdentifiers.PKI_STATUS)));
            Nonce recipientNonce = toNonce(attrTable
                    .get(toOid(ScepObjectIdentifiers.RECIPIENT_NONCE)));

            if (pkiStatus == PkiStatus.FAILURE) {
                FailInfo failInfo = toFailInfo(attrTable
                        .get(toOid(ScepObjectIdentifiers.FAIL_INFO)));

                decoded = new CertRep(transId, senderNonce, recipientNonce,
                        failInfo);
            } else if (pkiStatus == PkiStatus.PENDING) {

                decoded = new CertRep(transId, senderNonce, recipientNonce);
            } else {
                final EnvelopedData ed = getEnvelopedData((byte[]) signedContent
                        .getContent());
                final byte[] envelopedContent = decoder.decode(ed);
                DEROctetString messageData = new DEROctetString(
                        envelopedContent);

                decoded = new CertRep(transId, senderNonce, recipientNonce,
                        messageData.getOctets());
            }
        } else if (messageType == MessageType.GET_CERT) {
            EnvelopedData ed = getEnvelopedData((byte[]) signedContent
                    .getContent());
            IssuerAndSerialNumber messageData = new IssuerAndSerialNumber(
                    toDERSequence(decoder.decode(ed)));

            decoded = new GetCert(transId, senderNonce, messageData);
        } else if (messageType == MessageType.GET_CERT_INITIAL) {
            EnvelopedData ed = getEnvelopedData((byte[]) signedContent
                    .getContent());

            IssuerAndSubject messageData = new IssuerAndSubject(
                    decoder.decode(ed));

            decoded = new GetCertInitial(transId, senderNonce, messageData);
        } else if (messageType == MessageType.GET_CRL) {
            EnvelopedData ed = getEnvelopedData((byte[]) signedContent
                    .getContent());
            IssuerAndSerialNumber messageData = new IssuerAndSerialNumber(
                    toDERSequence(decoder.decode(ed)));

            decoded = new GetCRL(transId, senderNonce, messageData);
        } else {
            EnvelopedData ed = getEnvelopedData((byte[]) signedContent
                    .getContent());
            PKCS10CertificationRequest messageData = new PKCS10CertificationRequest(
                    decoder.decode(ed));

            decoded = new PKCSReq(transId, senderNonce, messageData);
        }

        LOGGER.debug("Decoded to: {}", decoded);
        return decoded;
    }

    private ASN1Sequence toDERSequence(byte[] bytes) {
        ASN1InputStream dIn = null;
        try {
            dIn = new ASN1InputStream(bytes);

            return (ASN1Sequence) dIn.readObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("badly encoded request");
        } finally {
            if (dIn != null) {
                try {
                    dIn.close();
                } catch (IOException e) {
                    LOGGER.error("Failed to close ASN.1 stream", e);
                }
            }
        }
    }

    private DERObjectIdentifier toOid(String oid) {
        return new DERObjectIdentifier(oid);
    }

    private EnvelopedData getEnvelopedData(byte[] bytes) throws IOException {
        // We expect the byte array to be a sequence
        // ... and that sequence to be a ContentInfo (but might be the
        // EnvelopedData)
        ContentInfo contentInfo = ContentInfo.getInstance(bytes);
        // If it *is* a ContentInfo, the content *should* be EnvelopedData
        ASN1Encodable content = contentInfo.getContent();

        return EnvelopedData.getInstance(content);
    }

    private Nonce toNonce(Attribute attr) {
        // Sometimes we don't get a sender nonce.
        if (attr == null) {
            return null;
        }
        final DEROctetString octets = (DEROctetString) attr.getAttrValues()
                .getObjectAt(0);

        return new Nonce(octets.getOctets());
    }

    private MessageType toMessageType(Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return MessageType.valueOf(Integer.valueOf(string.getString()));
    }

    private TransactionId toTransactionId(Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return new TransactionId(string.getOctets());
    }

    private PkiStatus toPkiStatus(Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.valueOf(string.getString()));
    }

    private FailInfo toFailInfo(Attribute attr) {
        final DERPrintableString string = (DERPrintableString) attr
                .getAttrValues().getObjectAt(0);

        return FailInfo.valueOf(Integer.valueOf(string.getString()));
    }
}
