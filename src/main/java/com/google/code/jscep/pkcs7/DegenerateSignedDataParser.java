package com.google.code.jscep.pkcs7;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.cms.CMSSignedData;

import com.google.code.jscep.util.LoggingUtil;

public class DegenerateSignedDataParser {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.pkcs7");
	public DegenerateSignedData parse(ASN1Encodable signedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse");
		
		try {
			final CertificateFactory factory = CertificateFactory.getInstance("X.509");
			SignedData pkcsSd = new SignedData((ASN1Sequence) signedData);
			Collection collection = new HashSet<Object>();
			ASN1Set certs = pkcsSd.getCertificates();
			ASN1Set crls = pkcsSd.getCRLs();
			Enumeration<?> certEnum = certs.getObjects();
			while (certEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) certEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				Certificate cert = factory.generateCertificate(bais);
				collection.add(cert);
			}
			Enumeration<?> crlEnum = crls.getObjects();
			while (crlEnum.hasMoreElements()) {
				ASN1Sequence o = (ASN1Sequence) certEnum.nextElement();
				ByteArrayInputStream bais = new ByteArrayInputStream(o.getDEREncoded());
				CRL crl = factory.generateCRL(bais);
				collection.add(crl);
			}
			CertStoreParameters parameters = new CollectionCertStoreParameters(collection);
			CertStore store = CertStore.getInstance("Collection", parameters);
//			CMSSignedData sd = new CMSSignedData(signedData.getDEREncoded());
//            CertStore store = sd.getCertificatesAndCRLs("Collection", "BC");
            
            DegenerateSignedDataImpl certRep = new DegenerateSignedDataImpl();
            certRep.setCertStore(store);
            certRep.setEncoded(signedData.getDEREncoded());
            
            LOGGER.exiting(getClass().getName(), "parse", certRep);
            return certRep;

		} catch (Exception e) {
			
			LOGGER.throwing(getClass().getName(), "parse", e);
			throw new IOException(e);
		}
	}
}
