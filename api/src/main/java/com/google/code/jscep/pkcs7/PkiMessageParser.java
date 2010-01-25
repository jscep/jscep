package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.google.code.jscep.transaction.PkiStatus;
import com.google.code.jscep.util.LoggingUtil;

public class PkiMessageParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	private PrivateKey privateKey;
	
	public PkiMessageParser() {
	}
	
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * @param msgBytes DER-encoded degenerate certificates-only signedData
	 * @return a new instance of PkiMessage
	 */
	public PkiMessage parse(byte[] msgBytes) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", msgBytes);

		final ContentInfo sdContentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(msgBytes));
		final SignedData signedData = SignedData.getInstance((ASN1Sequence) sdContentInfo.getContent());
		
		// 3.1 version MUST be 1
		assert(signedData.getVersion().getValue().equals(BigInteger.ONE));
		// 3.1 the contentType in contentInfo MUST be data
		assert(signedData.getEncapContentInfo().getContentType().equals(CMSObjectIdentifiers.data));
		
		final Set<SignerInfo> signerInfoSet = getSignerInfo(signedData);

		if (signerInfoSet.size() > 1) {
			IOException ioe = new IOException("Too Many SignerInfos");
			LOGGER.throwing(getClass().getName(), "parse", ioe);
			throw ioe;
		}

		final PkiMessage msg = new PkiMessage(sdContentInfo);
		if (msg.isRequest() || msg.getPkiStatus() == PkiStatus.SUCCESS) {
			final ContentInfo edContentInfo = signedData.getEncapContentInfo();
			final DEROctetString octetString = (DEROctetString) edContentInfo.getContent();
			final PkcsPkiEnvelopeParser envelopeParser = new PkcsPkiEnvelopeParser(privateKey);
			msg.setPkcsPkiEnvelope(envelopeParser.parse(octetString.getOctets()));	
		} else {
			// TODO: Assert No ContentInfo
			// http://tools.ietf.org/html/draft-nourse-scep-20#section-3
		}
		
		LOGGER.exiting(getClass().getName(), "parse", msg);
		return msg; 
	}
	
	private Set<SignerInfo> getSignerInfo(SignedData signedData) {
		final Set<SignerInfo> set = new HashSet<SignerInfo>();
		final Enumeration<?> signerInfos = signedData.getSignerInfos().getObjects();
		
		while (signerInfos.hasMoreElements()) {
			final ASN1Sequence seq = (ASN1Sequence) signerInfos.nextElement();
			set.add(new SignerInfo(seq));
		}
		
		return set;
	}
}
