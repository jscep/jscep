package com.google.code.jscep.pkcs7;

import java.io.IOException;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	public DegenerateSignedData parse(ASN1Encodable signedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");
		
		try {
			final BERConstructedOctetString octets = (BERConstructedOctetString) signedData;
			
			final ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(octets.getOctets());
			final ContentInfo ci = new ContentInfo(seq);
			System.out.println(ci.getContentType());
			SignedData sd = new SignedData((ASN1Sequence) ci.getContent());
			DegenerateSignedDataImpl certRep = new DegenerateSignedDataImpl(sd);

			LOGGER.exiting(getClass().getName(), "parse", certRep);
			return certRep;
		} catch (Exception e) {
			
			LOGGER.throwing(getClass().getName(), "parse", e);
			throw new IOException(e);
		}
	}
}
