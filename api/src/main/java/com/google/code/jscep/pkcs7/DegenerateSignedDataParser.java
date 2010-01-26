package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");

	public SignedData parse(ASN1Encodable signedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", signedData);
		
		try {
			ContentInfo ci = ContentInfo.getInstance(signedData);
			assert(ci.getContentType().equals(CMSObjectIdentifiers.data));
			ASN1Sequence seq = (ASN1Sequence) ci.getContent();
			final SignedData sd = new SignedData(seq);

			LOGGER.exiting(getClass().getName(), "parse", sd);
			return sd;
		} catch (Exception e) {
			
			LOGGER.throwing(getClass().getName(), "parse", e);
			throw new IOException(e);
		}
	}
}
