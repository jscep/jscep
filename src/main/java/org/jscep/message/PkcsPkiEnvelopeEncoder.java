package org.jscep.message;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used for enveloping and encrypting a <tt>messageData</tt> to
 * produce the <tt>pkcsPkiEnvelope</tt> part of a SCEP secure message object.
 * 
 * @see PkcsPkiEnvelopeDecoder
 */
public final class PkcsPkiEnvelopeEncoder {
	private static final Logger LOGGER = LoggerFactory
			.getLogger(PkcsPkiEnvelopeEncoder.class);
	private final X509Certificate recipient;

	/**
	 * Creates a new <tt>PkcsPkiEnvelopeEncoder</tt> for the entity identified
	 * by the provided certificate.
	 * 
	 * @param recipient
	 *            the entity for whom the <tt>pkcsPkiEnvelope</tt> is intended.
	 */
	public PkcsPkiEnvelopeEncoder(X509Certificate recipient) {
		this.recipient = recipient;
	}

	/**
	 * Encrypts and envelops the provided messageData.
	 * 
	 * @param messageData
	 *            the message data to encrypt and envelop.
	 * @return the enveloped data.
	 * @throws MessageEncodingException
	 *             if there are any problems encoding the message.
	 */
	public CMSEnvelopedData encode(byte[] messageData)
			throws MessageEncodingException {
		LOGGER.debug("Encoding pkcsPkiEnvelope");
		CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
		CMSTypedData envelopable = new CMSProcessableByteArray(messageData);
		RecipientInfoGenerator recipientGenerator;
		try {
			recipientGenerator = new JceKeyTransRecipientInfoGenerator(
					recipient);
		} catch (CertificateEncodingException e) {
			throw new MessageEncodingException(e);
		}
		edGenerator.addRecipientInfoGenerator(recipientGenerator);
		LOGGER.debug(
				"Encrypting pkcsPkiEnvelope using key belonging to [issuer={}; serial={}]",
				recipient.getIssuerDN(), recipient.getSerialNumber());

		OutputEncryptor encryptor;
		try {
			// TODO: Don't rely on using Triple DES
			encryptor = new JceCMSContentEncryptorBuilder(
					PKCSObjectIdentifiers.des_EDE3_CBC).build();
		} catch (CMSException e) {
			throw new MessageEncodingException(e);
		}
		try {
			CMSEnvelopedData pkcsPkiEnvelope = edGenerator.generate(
					envelopable, encryptor);

			LOGGER.debug("Finished encoding pkcsPkiEnvelope");
			return pkcsPkiEnvelope;
		} catch (CMSException e) {
			throw new MessageEncodingException(e);
		}
	}
}
