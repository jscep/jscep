package com.google.code.jscep.pkcs7;

import java.security.KeyPair;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

import com.google.code.jscep.transaction.CmsException;
import com.google.code.jscep.util.HexUtil;

public class PkcsPkiEnvelopeParser {
	private final static Logger LOGGER = Logger.getLogger(PkcsPkiEnvelopeParser.class.getName());
	private final KeyPair keyPair;
	
	public PkcsPkiEnvelopeParser(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	@SuppressWarnings("unchecked")
	public PkcsPkiEnvelope parse(byte[] envelopeBytes) throws CmsException {
		LOGGER.info("Incoming EnvelopedData:\n" + HexUtil.format(envelopeBytes));
		
		CMSEnvelopedData ed;
		try {
			ed = new CMSEnvelopedData(envelopeBytes);
		} catch (CMSException e) {
			throw new CmsException(e);
		}
		
		final RecipientInformationStore recipientStore = ed.getRecipientInfos();
		final Collection<RecipientInformation> recipientInfos = recipientStore.getRecipients();
    	final RecipientInformation recipient = recipientInfos.iterator().next();
    	
    	byte[] msgData;
		try {
			msgData = recipient.getContent(keyPair.getPrivate(), "BC");
		} catch (Exception e) {
			throw new CmsException(e);
		}

    	final PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl();
    	envelope.setMessageData(msgData);
    	envelope.setEncoded(envelopeBytes);
    	
		return envelope;
	}
}
