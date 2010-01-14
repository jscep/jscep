package com.google.code.jscep.pkcs7;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	public DegenerateSignedData parse(ASN1Encodable signedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");
		
		try {
			ContentInfo ci = ContentInfo.getInstance(signedData);
			assert(ci.getContentType().equals(CMSObjectIdentifiers.signedData));
			ASN1Sequence seq = (ASN1Sequence) ci.getContent();
			final CertificateFactory factory = CertificateFactory.getInstance("X.509");
			SignedData sd = new SignedData(seq);
			Collection collection = new HashSet<Object>();
			ASN1Set certs = sd.getCertificates();
			ASN1Set crls = sd.getCRLs();
			if (certs != null) {
				Enumeration<?> certEnum = certs.getObjects();
				while (certEnum.hasMoreElements()) {
					ASN1Sequence o = (ASN1Sequence) certEnum.nextElement();
					ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
					Certificate cert = factory.generateCertificate(bais);
					collection.add(cert);
				}
			}
			if (crls != null) {
				Enumeration<?> crlEnum = crls.getObjects();
				while (crlEnum.hasMoreElements()) {
					ASN1Sequence o = (ASN1Sequence) crlEnum.nextElement();
					ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
					CRL crl = factory.generateCRL(bais);
					collection.add(crl);
				}
			}
			CertStoreParameters parameters = new CollectionCertStoreParameters(collection);
			CertStore store = CertStore.getInstance("Collection", parameters);
            
            DegenerateSignedDataImpl certRep = new DegenerateSignedDataImpl(store, signedData.getDEREncoded());
            
            LOGGER.exiting(getClass().getName(), "parse", certRep);
            return certRep;

		} catch (Exception e) {
			
			LOGGER.throwing(getClass().getName(), "parse", e);
			throw new IOException(e);
		}
	}
}
