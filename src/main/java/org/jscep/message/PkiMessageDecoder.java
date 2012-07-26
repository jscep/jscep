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

import static org.jscep.asn1.ScepObjectIdentifier.FAIL_INFO;
import static org.jscep.asn1.ScepObjectIdentifier.MESSAGE_TYPE;
import static org.jscep.asn1.ScepObjectIdentifier.PKI_STATUS;
import static org.jscep.asn1.ScepObjectIdentifier.RECIPIENT_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.SENDER_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.TRANS_ID;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.asn1.ScepObjectIdentifier;
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
    private final X509Certificate signer;

    public PkiMessageDecoder(PkcsPkiEnvelopeDecoder decoder, X509Certificate signer) {
        this.decoder = decoder;
        this.signer = signer;
    }

    @SuppressWarnings("unchecked")
    public PkiMessage<?> decode(CMSSignedData signedData) throws MessageDecodingException {
        // The signed content is always an octet string
        CMSProcessable signedContent = signedData.getSignedContent();

        SignerInformationStore signerStore = signedData.getSignerInfos();
        SignerInformation signerInfo = signerStore.get(new JcaSignerId(signer));
        Store store = signedData.getCertificates();
        Collection<?> certColl;
        try {
            certColl = store.getMatches(signerInfo.getSID());
        } catch (StoreException e) {
            throw new MessageDecodingException(e);
        }
        if (certColl.size() > 0) {
            X509CertificateHolder cert = (X509CertificateHolder) certColl
                    .iterator().next();
            LOGGER.debug("Verifying message using key belonging to '{}'",
                    cert.getSubject());
            SignerInformationVerifier verifier;
            try {
                verifier = new JcaSimpleSignerInfoVerifierBuilder().build(cert);
                signerInfo.verify(verifier);
            } catch (Exception e) {
                throw new MessageDecodingException(e);
            }
        } else {
            LOGGER.error("Unable to verify message");
        }

        Hashtable<DERObjectIdentifier, Attribute> attrTable = signerInfo
                .getSignedAttributes().toHashtable();

        MessageType messageType = toMessageType(attrTable
                .get(toOid(MESSAGE_TYPE)));
        Nonce senderNonce = toNonce(attrTable
                .get(toOid(SENDER_NONCE)));
        TransactionId transId = toTransactionId(attrTable
                .get(toOid(TRANS_ID)));

        PkiMessage<?> pkiMessage;
        if (messageType == MessageType.CERT_REP) {
            PkiStatus pkiStatus = toPkiStatus(attrTable
                    .get(toOid(PKI_STATUS)));
            Nonce recipientNonce = toNonce(attrTable
                    .get(toOid(RECIPIENT_NONCE)));

            if (pkiStatus == PkiStatus.FAILURE) {
                FailInfo failInfo = toFailInfo(attrTable
                        .get(toOid(FAIL_INFO)));

                pkiMessage = new CertRep(transId, senderNonce, recipientNonce,
                        failInfo);
            } else if (pkiStatus == PkiStatus.PENDING) {

                pkiMessage = new CertRep(transId, senderNonce, recipientNonce);
            } else {
                final CMSEnvelopedData ed = getEnvelopedData(signedContent
                        .getContent());
                final byte[] envelopedContent = decoder.decode(ed);
                DEROctetString messageData = new DEROctetString(
                        envelopedContent);

                pkiMessage = new CertRep(transId, senderNonce, recipientNonce,
                        messageData.getOctets());
            }
        } else {
            CMSEnvelopedData ed = getEnvelopedData(signedContent.getContent());
            byte[] decoded = decoder.decode(ed);
            if (messageType == MessageType.GET_CERT) {
                IssuerAndSerialNumber messageData = IssuerAndSerialNumber
                        .getInstance(decoded);

                pkiMessage = new GetCert(transId, senderNonce, messageData);
            } else if (messageType == MessageType.GET_CERT_INITIAL) {
                IssuerAndSubject messageData = new IssuerAndSubject(decoded);

                pkiMessage = new GetCertInitial(transId, senderNonce,
                        messageData);
            } else if (messageType == MessageType.GET_CRL) {
                IssuerAndSerialNumber messageData = IssuerAndSerialNumber
                        .getInstance(decoded);

                pkiMessage = new GetCrl(transId, senderNonce, messageData);
            } else {
                PKCS10CertificationRequest messageData;
                try {
                    messageData = new PKCS10CertificationRequest(decoded);
                } catch (IOException e) {
                    throw new MessageDecodingException(e);
                }

                pkiMessage = new PkcsReq(transId, senderNonce, messageData);
            }
        }

        LOGGER.debug("Decoded to: {}", pkiMessage);
        return pkiMessage;
    }

    private DERObjectIdentifier toOid(ScepObjectIdentifier oid) {
        return new DERObjectIdentifier(oid.id());
    }

    private CMSEnvelopedData getEnvelopedData(Object bytes)
            throws MessageDecodingException {
        // We expect the byte array to be a sequence
        // ... and that sequence to be a ContentInfo (but might be the
        // EnvelopedData)
        try {
            return new CMSEnvelopedData((byte[]) bytes);
        } catch (CMSException e) {
            throw new MessageDecodingException(e);
        }
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
