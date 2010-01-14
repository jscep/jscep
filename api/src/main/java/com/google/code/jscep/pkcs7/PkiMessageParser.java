package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import com.google.code.jscep.transaction.CmsException;
import com.google.code.jscep.transaction.FailInfo;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.transaction.Nonce;
import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.transaction.ScepObjectIdentifiers;
import com.google.code.jscep.transaction.TransactionId;
import com.google.code.jscep.util.HexUtil;
import com.google.code.jscep.util.LoggingUtil;

public class PkiMessageParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private AttributeTable signedAttrs;
	private final PkcsPkiEnvelopeParser parser;
	
	public PkiMessageParser(PkcsPkiEnvelopeParser parser) {
		this.parser = parser;
	}
	
	/**
	 * @param msgBytes DER-encoded degenerate certificates-only signedData
	 * @return a new instance of PkiMessage
	 * @throws CmsException
	 */
	public PkiMessage parse(byte[] msgBytes) throws IOException {
		LOGGER.info("Incoming SignedData:\n" + HexUtil.format(msgBytes));
		SignedData cmsSd;
		CMSSignedData signedData;
		try {
			ASN1Object obj = ASN1Object.fromByteArray(msgBytes);
			ContentInfo info = ContentInfo.getInstance(obj);
			assert(info.getContentType().equals(CMSObjectIdentifiers.signedData));
			ASN1Sequence seq = (ASN1Sequence) info.getContent();
			cmsSd = SignedData.getInstance(seq);
			signedData = new CMSSignedData(msgBytes);
		} catch (CMSException e) {
			
			IOException ioe = new IOException(e);
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}
    	SignerInformationStore store = signedData.getSignerInfos();
        Collection<?> signers = store.getSigners();
        
        if (signers.size() > 1) {

        	IOException ioe = new IOException("Too Many SignerInfos");
			LOGGER.throwing(getClass().getName(), "parse", ioe);
        	throw ioe;
        }
        
        SignerInformation signerInformation = (SignerInformation) signers.iterator().next();
        signedAttrs = signerInformation.getSignedAttributes();

        final CMSProcessable signedContent = signedData.getSignedContent();
		byte[] envelopedData = (byte[]) signedContent.getContent();
		
		final PkiMessageImpl msg = new PkiMessageImpl();
		msg.setTransactionId(extractTransactionId());
		msg.setRecipientNonce(extractRecipientNonce());
		msg.setSenderNonce(extractSenderNonce());
		msg.setStatus(extractStatus());
		msg.setMessageType(extractMessageType());
		msg.setPkcsPkiEnvelope(parser.parse(envelopedData));
		
		if (msg.getStatus() == PkiStatus.FAILURE) {
			msg.setFailInfo(extractFailInfo());
		}
		
		return msg; 
	}
	
	private TransactionId extractTransactionId() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.transId);
        Attribute transIdAttr = signedAttrs.get(oid);
        DERPrintableString transId = (DERPrintableString) transIdAttr.getAttrValues().getObjectAt(0);
        
        return new TransactionId(transId.getOctets());
	}

	private FailInfo extractFailInfo() {
		DERObjectIdentifier oid;
		oid = new DERObjectIdentifier(ScepObjectIdentifiers.failInfo);
		Attribute failInfoAttribute = signedAttrs.get(oid);
		DERPrintableString failInfo = (DERPrintableString) failInfoAttribute.getAttrValues().getObjectAt(0);
		
		return FailInfo.valueOf(Integer.parseInt(failInfo.getString()));
	}

	private Nonce extractRecipientNonce() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.recipientNonce);
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}
	
	private Nonce extractSenderNonce() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.senderNonce);
        Attribute recipientNonceAttribute = signedAttrs.get(oid);
        DEROctetString attr = (DEROctetString) recipientNonceAttribute.getAttrValues().getObjectAt(0);
        
        return new Nonce(attr.getOctets());
	}

	private PkiStatus extractStatus() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.pkiStatus);
        Attribute attr = signedAttrs.get(oid);
        DERPrintableString pkiStatus = (DERPrintableString) attr.getAttrValues().getObjectAt(0);

        return PkiStatus.valueOf(Integer.parseInt(pkiStatus.toString()));
	}
	
	private MessageType extractMessageType() {
		DERObjectIdentifier oid = new DERObjectIdentifier(ScepObjectIdentifiers.messageType);
        Attribute msgTypeAttribute = signedAttrs.get(oid);
        DERPrintableString msgType = (DERPrintableString) msgTypeAttribute.getAttrValues().getObjectAt(0);
        
        return MessageType.valueOf(Integer.parseInt(msgType.getString()));
	}
}
