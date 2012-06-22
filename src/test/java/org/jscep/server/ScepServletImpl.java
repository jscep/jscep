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
import java.util.Date;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
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
	private X500Name name;
	private X500Name pollName;
	private BigInteger caSerial;

	public void init(ServletContext context) {
		LOGGER.debug("INIT");
	}

	@Override
	public void init() throws ServletException {
		name = new X500Name("CN=Certification Authority");
		pollName = new X500Name("CN=Poll");
		caSerial = BigInteger.TEN;
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
			X500Name subject, X500Name issuer, BigInteger serial)
			throws Exception {
		Calendar cal = GregorianCalendar.getInstance();
		cal.add(Calendar.YEAR, -1);
		Date notBefore = cal.getTime();

		cal.add(Calendar.YEAR, 2);
		Date notAfter = cal.getTime();

		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				issuer, serial, notBefore, notAfter, subject, pubKey);
		builder.addExtension(X509Extension.basicConstraints, true,
				new BasicConstraints(0));

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder("SHA1withRSA").build(priKey);
		} catch (OperatorCreationException e) {
			throw new Exception(e);
		}
		X509CertificateHolder holder = builder.build(signer);
		return new JcaX509CertificateConverter().getCertificate(holder);
	}

	@Override
	protected List<X509Certificate> doEnrol(PKCS10CertificationRequest csr)
			throws OperationFailureException {
		try {
			X500Name subject = X500Name.getInstance(csr.getSubject());
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
					getSerial());

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

	private BigInteger getSerial() {
		Random rnd = new Random();
		return BigInteger.valueOf(Math.abs(rnd.nextLong()) + 1);
	}

	private String getPassword(PKCS10CertificationRequest csr) {
		Attribute[] attrs = csr.getAttributes();
		for (Attribute attr : attrs) {
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
	protected X509CRL doGetCrl(X500Name issuer, BigInteger serial)
			throws OperationFailureException {
		return null;
	}

	@Override
	protected Set<Capability> doCapabilities(String identifier) {
		return EnumSet.of(Capability.SHA_1, Capability.POST_PKI_OPERATION);
	}

	@Override
	protected List<X509Certificate> doGetCert(X500Name issuer, BigInteger serial)
			throws OperationFailureException {
		IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);

		LOGGER.debug("Searching cache for {}, {}", iasn.getName(),
				iasn.getSerialNumber());
		if (CACHE.containsKey(iasn)) {
			return Collections.singletonList(CACHE.get(iasn));
		}
		throw new OperationFailureException(FailInfo.badCertId);
	}

	@Override
	protected List<X509Certificate> doGetCertInitial(X500Name issuer,
			X500Name subject) throws OperationFailureException {
		if (subject.equals(pollName)) {
			return Collections.emptyList();
		}
		try {
			return Collections.singletonList(generateCertificate(pubKey,
					subject, issuer, getSerial()));
		} catch (Exception e) {
			throw new OperationFailureException(FailInfo.badCertId);
		}
	}

	@Override
	protected List<X509Certificate> getNextCaCertificate(String identifier) {
		if (identifier == null || identifier.length() == 0) {
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
