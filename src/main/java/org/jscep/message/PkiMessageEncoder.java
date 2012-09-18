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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.transaction.PkiStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to encode a <tt>pkiMessage</tt> into a PKCS #7 signedData
 * object.
 * 
 * @see PkiMessageDecoder
 */
public final class PkiMessageEncoder {
	private static final String DATA = "1.2.840.113549.1.7.1";
	private static final Logger LOGGER = LoggerFactory
			.getLogger(PkiMessageEncoder.class);
	private final PrivateKey signerKey;
	private final X509Certificate signerId;
	private final PkcsPkiEnvelopeEncoder enveloper;
	private final String signatureAlgorithm;

	/**
	 * Creates a new <tt>PkiMessageEncoder</tt> instance.
	 * 
	 * @param signerKey
	 *            the key to use to sign the <tt>signedData</tt>.
	 * @param signerId
	 *            the certificate to use to identify the signer.
	 * @param enveloper
	 *            the enveloper used for encoding the <tt>messageData</tt>
	 */
	public PkiMessageEncoder(PrivateKey signerKey, X509Certificate signerId,
			PkcsPkiEnvelopeEncoder enveloper) {
		this.signerKey = signerKey;
		this.signerId = signerId;
		this.enveloper = enveloper;
		this.signatureAlgorithm = "SHA1withRSA";
	}
	
	/**
	 * Creates a new <tt>PkiMessageEncoder</tt> instance.
	 * 
	 * @param signerKey
	 *            the key to use to sign the <tt>signedData</tt>.
	 * @param signerId
	 *            the certificate to use to identify the signer.
	 * @param enveloper
	 *            the enveloper used for encoding the <tt>messageData</tt>
	 */
	public PkiMessageEncoder(PrivateKey signerKey, X509Certificate signerId,
			PkcsPkiEnvelopeEncoder enveloper, String signatureAlgorithm) {
		this.signerKey = signerKey;
		this.signerId = signerId;
		this.enveloper = enveloper;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * Encodes the provided <tt>PkiMessage</tt> into a PKCS #7
	 * <tt>signedData</tt>.
	 * 
	 * @param message
	 *            the <tt>PkiMessage</tt> to encode.
	 * @return the encoded <tt>signedData</tt>
	 * @throws MessageEncodingException
	 *             if there is a problem encoding the <tt>PkiMessage</tt>
	 */
	public CMSSignedData encode(PkiMessage<?> message)
			throws MessageEncodingException {
		LOGGER.debug("Encoding pkiMessage");
		LOGGER.debug("Encoding message: {}", message);

		CMSProcessable content = getContent(message);
		LOGGER.debug(
				"Signing pkiMessage using key belonging to [issuer={}; serial={}]",
				signerId.getIssuerDN(), signerId.getSerialNumber());
		try {
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			generator.addSignerInfoGenerator(getSignerInfo(message));
			generator.addCertificates(getCertificates());
			LOGGER.debug("Signing {} content", content);
			CMSSignedData pkiMessage = generator.generate(DATA, content, true,
					(Provider) null, true);
			LOGGER.debug("Finished encoding pkiMessage");

			return pkiMessage;
		} catch (CMSException e) {
			throw new MessageEncodingException(e);
		} catch (Exception e) {
			throw new MessageEncodingException(e);
		}
	}

	private CMSProcessable getContent(PkiMessage<?> message)
			throws MessageEncodingException {
		CMSProcessable signable;

		boolean hasMessageData = true;
		if (message instanceof CertRep) {
			CertRep response = (CertRep) message;
			if (response.getPkiStatus() != PkiStatus.SUCCESS) {
				hasMessageData = false;
			}
		}
		if (hasMessageData) {
			try {
				CMSEnvelopedData ed = encodeMessage(message);
				signable = new CMSProcessableByteArray(ed.getEncoded());
			} catch (IOException e) {
				throw new MessageEncodingException(e);
			}
		} else {
			signable = new CMSAbsentContent();
		}
		return signable;
	}

	private CMSEnvelopedData encodeMessage(PkiMessage<?> message)
			throws MessageEncodingException {
		Object messageData = message.getMessageData();
		byte[] bytes;
		if (messageData instanceof byte[]) {
			bytes = (byte[]) messageData;
		} else if (messageData instanceof PKCS10CertificationRequest) {
			try {
				bytes = ((PKCS10CertificationRequest) messageData).getEncoded();
			} catch (IOException e) {
				throw new MessageEncodingException(e);
			}
		} else if (messageData instanceof CMSSignedData) {
			try {
				bytes = ((CMSSignedData) messageData).getEncoded();
			} catch (IOException e) {
				throw new MessageEncodingException(e);
			}
		} else {
			try {
				bytes = ((ASN1Object) messageData).getEncoded();
			} catch (IOException e) {
				throw new MessageEncodingException(e);
			}
		}
		return enveloper.encode(bytes);
	}

	private JcaCertStore getCertificates() throws MessageEncodingException {
		Collection<X509Certificate> certColl = Collections.singleton(signerId);
		JcaCertStore certStore;
		try {
			certStore = new JcaCertStore(certColl);
		} catch (CertificateEncodingException e) {
			throw new MessageEncodingException(e);
		}
		return certStore;
	}

	private SignerInfoGenerator getSignerInfo(PkiMessage<?> message)
			throws MessageEncodingException {
		JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
				getDigestCalculator());
		signerInfoBuilder
				.setSignedAttributeGenerator(getTableGenerator(message));
		SignerInfoGenerator signerInfo;
		try {
			signerInfo = signerInfoBuilder.build(getContentSigner(), signerId);
		} catch (Exception e) {
			throw new MessageEncodingException(e);
		}
		return signerInfo;
	}

	private CMSAttributeTableGenerator getTableGenerator(PkiMessage<?> message) {
		AttributeTableFactory attrFactory = new AttributeTableFactory();
		AttributeTable signedAttrs = attrFactory.fromPkiMessage(message);
		CMSAttributeTableGenerator atGen = new DefaultSignedAttributeTableGenerator(
				signedAttrs);
		return atGen;
	}

	private DigestCalculatorProvider getDigestCalculator()
			throws MessageEncodingException {
		try {
			return new JcaDigestCalculatorProviderBuilder().build();
		} catch (OperatorCreationException e) {
			throw new MessageEncodingException(e);
		}
	}

	private ContentSigner getContentSigner() throws OperatorCreationException {
		return new JcaContentSignerBuilder(signatureAlgorithm).build(signerKey);
	}
}
