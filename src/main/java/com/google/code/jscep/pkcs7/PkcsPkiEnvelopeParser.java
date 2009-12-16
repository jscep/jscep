package com.google.code.jscep.pkcs7;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

import com.google.code.jscep.util.HexUtil;

public class PkcsPkiEnvelopeParser {
	private final static Logger LOGGER = Logger.getLogger(PkcsPkiEnvelopeParser.class.getName());
	private final KeyPair keyPair;
	
	public PkcsPkiEnvelopeParser(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	public PkcsPkiEnvelope parse(byte[] envelopeBytes) throws CMSException, GeneralSecurityException {
		LOGGER.info("Incoming EnvelopedData:\n" + HexUtil.format(envelopeBytes));
		final CMSEnvelopedData ed = new CMSEnvelopedData(envelopeBytes);
		final RecipientInformationStore recipientStore = ed.getRecipientInfos();
		final Collection<RecipientInformation> recipientInfos = recipientStore.getRecipients();
    	final RecipientInformation recipient = recipientInfos.iterator().next();
    	final byte[] msgData = recipient.getContent(keyPair.getPrivate(), "BC");

    	final PkcsPkiEnvelopeImpl envelope = new PkcsPkiEnvelopeImpl();
    	envelope.setMessageData(msgData);
    	envelope.setEncoded(envelopeBytes);
    	
		return envelope;
	}
}
