package org.jscep.message;

import static org.jscep.asn1.ScepObjectIdentifier.FAIL_INFO;
import static org.jscep.asn1.ScepObjectIdentifier.MESSAGE_TYPE;
import static org.jscep.asn1.ScepObjectIdentifier.PKI_STATUS;
import static org.jscep.asn1.ScepObjectIdentifier.RECIPIENT_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.SENDER_NONCE;
import static org.jscep.asn1.ScepObjectIdentifier.TRANS_ID;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
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

/**
 * This class is used to decode a PKCS #7 signedData object into a
 * <tt>pkiMessage</tt>.
 * 
 * @see PkiMessageEncoder
 */
public final class PkiMessageDecoder {
    private static final Logger LOGGER = getLogger(PkiMessageDecoder.class);
    private final PkcsPkiEnvelopeDecoder decoder;
    private final X509Certificate signer;

    /**
     * Creates a new <tt>PkiMessageDecoder</tt>.
     * 
     * @param signer
     *            the certificate used for verifying the <tt>signedData</tt>
     *            signature.
     * @param decoder
     *            the decoder used for extracting the <tt>pkiMessage</tt>.
     */
    public PkiMessageDecoder(X509Certificate signer,
	    PkcsPkiEnvelopeDecoder decoder) {
	this.decoder = decoder;
	this.signer = signer;
    }

    /**
     * Decodes the provided PKCS #7 <tt>signedData</tt> into a
     * <tt>PkiMessage</tt>
     * 
     * @param pkiMessage
     *            the <tt>signedData</tt> to decode.
     * @return the decoded <tt>PkiMessage</tt>
     * @throws MessageDecodingException
     *             if there is a problem decoding the <tt>signedData</tt>
     */
    @SuppressWarnings("unchecked")
    public PkiMessage<?> decode(CMSSignedData pkiMessage)
	    throws MessageDecodingException {
	LOGGER.debug("Decoding pkiMessage");
	validate(pkiMessage);

	// The signed content is always an octet string
	CMSProcessable signedContent = pkiMessage.getSignedContent();

	SignerInformationStore signerStore = pkiMessage.getSignerInfos();
	SignerInformation signerInfo = signerStore.get(new JcaSignerId(signer));
	if (signerInfo == null) {
	    throw new MessageDecodingException("Could not for signerInfo for "
		    + signer.getIssuerDN());
	}
	Store store = pkiMessage.getCertificates();
	Collection<?> certColl;
	try {
	    certColl = store.getMatches(signerInfo.getSID());
	} catch (StoreException e) {
	    throw new MessageDecodingException(e);
	}
	if (certColl.size() > 0) {
	    X509CertificateHolder cert = (X509CertificateHolder) certColl
		    .iterator().next();
	    LOGGER.debug(
		    "Verifying pkiMessage using key belonging to [issuer={}; serial={}]",
		    cert.getIssuer(), cert.getSerialNumber());
	    SignerInformationVerifier verifier;
	    try {
		verifier = new JcaSimpleSignerInfoVerifierBuilder().build(cert);
		signerInfo.verify(verifier);

		LOGGER.debug("pkiMessage verified.");
	    } catch (Exception e) {
		throw new MessageDecodingException(e);
	    }
	} else {
	    LOGGER.warn("Unable to verify message because the signedData contained no certificates.");
	}

	Hashtable<DERObjectIdentifier, Attribute> attrTable = signerInfo
		.getSignedAttributes().toHashtable();

	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("pkiMessage has {} signed attributes:", signerInfo
		    .getSignedAttributes().size());
	    for (DERObjectIdentifier oid : attrTable.keySet()) {
		LOGGER.debug("  {}: {}", oid.getId(), attrTable.get(oid)
			.getAttrValues());
	    }
	}

	MessageType messageType = toMessageType(attrTable
		.get(toOid(MESSAGE_TYPE)));
	Nonce senderNonce = toNonce(attrTable.get(toOid(SENDER_NONCE)));
	TransactionId transId = toTransactionId(attrTable.get(toOid(TRANS_ID)));

	if (messageType == MessageType.CERT_REP) {
	    PkiStatus pkiStatus = toPkiStatus(attrTable.get(toOid(PKI_STATUS)));
	    Nonce recipientNonce = toNonce(attrTable
		    .get(toOid(RECIPIENT_NONCE)));

	    if (pkiStatus == PkiStatus.FAILURE) {
		FailInfo failInfo = toFailInfo(attrTable.get(toOid(FAIL_INFO)));
		LOGGER.debug("Finished decoding pkiMessage");
		return new CertRep(transId, senderNonce, recipientNonce,
			failInfo);
	    } else if (pkiStatus == PkiStatus.PENDING) {
		LOGGER.debug("Finished decoding pkiMessage");
		return new CertRep(transId, senderNonce, recipientNonce);
	    } else {
		final CMSEnvelopedData ed = getEnvelopedData(signedContent
			.getContent());
		final byte[] envelopedContent = decoder.decode(ed);
		CMSSignedData messageData;
		try {
		    messageData = new CMSSignedData(envelopedContent);
		} catch (CMSException e) {
		    throw new MessageDecodingException(e);
		}
		LOGGER.debug("Finished decoding pkiMessage");
		return new CertRep(transId, senderNonce, recipientNonce,
			messageData);
	    }
	} else {
	    CMSEnvelopedData ed = getEnvelopedData(signedContent.getContent());
	    byte[] decoded = decoder.decode(ed);
	    if (messageType == MessageType.GET_CERT) {
		IssuerAndSerialNumber messageData = IssuerAndSerialNumber
			.getInstance(decoded);
		LOGGER.debug("Finished decoding pkiMessage");
		return new GetCert(transId, senderNonce, messageData);
	    } else if (messageType == MessageType.GET_CERT_INITIAL) {
		IssuerAndSubject messageData = new IssuerAndSubject(decoded);
		LOGGER.debug("Finished decoding pkiMessage");
		return new GetCertInitial(transId, senderNonce, messageData);
	    } else if (messageType == MessageType.GET_CRL) {
		IssuerAndSerialNumber messageData = IssuerAndSerialNumber
			.getInstance(decoded);
		LOGGER.debug("Finished decoding pkiMessage");
		return new GetCrl(transId, senderNonce, messageData);
	    } else {
		PKCS10CertificationRequest messageData;
		try {
		    messageData = new PKCS10CertificationRequest(decoded);
		} catch (IOException e) {
		    throw new MessageDecodingException(e);
		}
		LOGGER.debug("Finished decoding pkiMessage");
		return new PkcsReq(transId, senderNonce, messageData);
	    }
	}
    }

    private void validate(CMSSignedData pkiMessage) {
	SignedData sd = SignedData.getInstance(pkiMessage.toASN1Structure()
		.getContent());
	LOGGER.debug("pkiMessage version: {}", sd.getVersion());
	LOGGER.debug("pkiMessage contentInfo contentType: {}", sd
		.getEncapContentInfo().getContentType());
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
