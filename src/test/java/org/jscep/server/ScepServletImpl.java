package org.jscep.server;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.jscep.response.Capability;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;
import org.jscep.x509.X509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScepServletImpl extends ScepServlet {
	/**
     *
     */
	private static final Logger LOGGER = LoggerFactory
			.getLogger(ScepServletImpl.class);
	private static final Map<IssuerAndSerialNumber, X509Certificate> CACHE = new HashMap<IssuerAndSerialNumber, X509Certificate>();
	private static final long serialVersionUID = 1L;
	private PrivateKey priKey;
	private PublicKey pubKey;
	private X509Certificate ca;
	private X509Name name;
	private X509Name pollName;
	private BigInteger caSerial;
	private BigInteger goodSerial;

	public void init(ServletContext context) {
		LOGGER.debug("INIT");
	}

	@Override
	public void init() throws ServletException {
		name = new X509Name("CN=Certification Authority");
		pollName = new X509Name("CN=Poll");
		caSerial = BigInteger.TEN;
		goodSerial = BigInteger.ONE;
		try {
			KeyPair keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
			priKey = keyPair.getPrivate();
			pubKey = keyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException(e);
		}
		try {
			ca = generateCertificate(pubKey, name, name, caSerial);
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}

	private X509Certificate generateCertificate(PublicKey pubKey,
			X509Name subject, X509Name issuer, BigInteger serial)
			throws Exception {
		X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
		generator.setIssuerDN(issuer);

		Calendar cal = GregorianCalendar.getInstance();
		cal.add(Calendar.YEAR, -1);
		generator.setNotBefore(cal.getTime());

		cal.add(Calendar.YEAR, 2);
		generator.setNotAfter(cal.getTime());

		generator.setPublicKey(pubKey);
		generator.setSerialNumber(serial);
		generator.setSignatureAlgorithm("SHA1withRSA");
		generator.setSubjectDN(subject);
		generator.addExtension(X509Extensions.BasicConstraints, true,
				new BasicConstraints(0));

		return generator.generate(priKey);
	}

	@Override
	protected List<X509Certificate> doEnroll(PKCS10CertificationRequest csr)
			throws OperationFailureException {
		try {
			X509Name subject = csr.getCertificationRequestInfo().getSubject();
			LOGGER.debug(subject.toString());
			if (subject.equals(pollName)) {
				return Collections.emptyList();
			}
			String password = getPassword(csr);
			if (!password.equals("password")) {
				LOGGER.debug("Invalid password");
				throw new OperationFailureException(FailInfo.badRequest);
			}
			PublicKey pubKey = X509Util.getPublicKey(csr);
			X509Certificate issued = generateCertificate(pubKey, subject, name,
					goodSerial);

			LOGGER.debug("Issuing {}", issued);
			CACHE.put(
					new IssuerAndSerialNumber(name, issued.getSerialNumber()),
					issued);

			return Collections.singletonList(issued);
		} catch (Exception e) {
			LOGGER.debug("Error in enrollment", e);
			throw new OperationFailureException(FailInfo.badRequest);
		}
	}

	private String getPassword(PKCS10CertificationRequest csr) {
		ASN1Set attrs = csr.getCertificationRequestInfo().getAttributes();
		Enumeration<?> objs = attrs.getObjects();
		while (objs.hasMoreElements()) {
			Attribute attr = new Attribute((DERSequence) objs.nextElement());
			if (attr.getAttrType().equals(
					PKCSObjectIdentifiers.pkcs_9_at_challengePassword)) {
				DERPrintableString password = (DERPrintableString) attr
						.getAttrValues().getObjectAt(0);
				return password.getString();
			}
		}
		return null;
	}

	@Override
	protected List<X509Certificate> doGetCaCertificate(String identifier) {
		return Collections.singletonList(ca);
	}

	@Override
	protected X509CRL doGetCrl(X509Name issuer, BigInteger serial)
			throws OperationFailureException {
		return null;
	}

	@Override
	protected Set<Capability> doCapabilities(String identifier) {
		return EnumSet.of(Capability.SHA_1, Capability.POST_PKI_OPERATION);
	}

	@Override
	protected List<X509Certificate> doGetCert(X509Name issuer, BigInteger serial)
			throws OperationFailureException {
		IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);

		LOGGER.debug("Searching cache for {}, {}", iasn.getName(),
				iasn.getSerialNumber());
		if (CACHE.containsKey(iasn)) {
			return Collections.singletonList(CACHE.get(iasn));
		} else if (serial.equals(goodSerial)) {
			try {
				return Collections.singletonList(generateCertificate(pubKey,
						issuer, issuer, goodSerial));
			} catch (Exception e) {
				throw new OperationFailureException(FailInfo.badCertId);
			}
		}
		throw new OperationFailureException(FailInfo.badCertId);
	}

	@Override
	protected List<X509Certificate> doGetCertInitial(X509Name issuer,
			X509Name subject) throws OperationFailureException {
		if (subject.equals(pollName)) {
			return Collections.emptyList();
		}
		try {
			return Collections.singletonList(generateCertificate(pubKey,
					subject, issuer, goodSerial));
		} catch (Exception e) {
			throw new OperationFailureException(FailInfo.badCertId);
		}
	}

	@Override
	protected List<X509Certificate> getNextCaCertificate(String identifier) {
		if (identifier == null || identifier.isEmpty()) {
			return Collections.singletonList(ca);
		}
		return Collections.emptyList();
	}

	@Override
	protected PrivateKey getPrivate() {
		return priKey;
	}

	@Override
	protected X509Certificate getSender() {
		return ca;
	}

}
