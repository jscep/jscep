package org.jscep.server;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.jscep.response.Capability;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;
import org.jscep.x509.X509Util;

public class ScepServletImpl extends ScepServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private PrivateKey priKey;
	private PublicKey pubKey;
	private X509Certificate ca;
	private X509Name name;
	private X509Name pollName;
	private BigInteger caSerial;
	private BigInteger goodSerial;
	
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
	
	private X509Certificate generateCertificate(PublicKey pubKey, X509Name subject, X509Name issuer, BigInteger serial) throws Exception {
		X509V1CertificateGenerator generator = new X509V1CertificateGenerator();
		generator.setIssuerDN(issuer);
		generator.setNotAfter(new Date());
		generator.setNotBefore(new Date());
		generator.setPublicKey(pubKey);
		generator.setSerialNumber(caSerial);
		generator.setSignatureAlgorithm("SHA1withRSA");
		generator.setSubjectDN(name);
		
		return generator.generate(priKey);
	}
	
	protected List<X509Certificate> doEnroll(CertificationRequest csr) throws OperationFailureException {
		try {
			X509Name subject = csr.getCertificationRequestInfo().getSubject();
			
			if (subject.equals(pollName)) {
				return Collections.<X509Certificate>emptyList();
			}
			PublicKey pubKey = X509Util.getPublicKey(csr);
			X509Certificate issued = generateCertificate(pubKey, subject, name, BigInteger.TEN);
			
			return Collections.singletonList(issued);
		} catch (Exception e) {
			throw new OperationFailureException(FailInfo.badRequest);
		}
	}

	@Override
	protected List<X509Certificate> doGetCaCertificate(String identifier) {
		return Collections.singletonList(ca);
	}

	@Override
	protected X509CRL doGetCrl(X509Name issuer, BigInteger serial) throws OperationFailureException {
		return null;
	}

	@Override
	protected Set<Capability> doCapabilities(String identifier) {
		return EnumSet.of(Capability.SHA_1, Capability.POST_PKI_OPERATION);
	}

	@Override
	protected List<X509Certificate> doGetCert(X509Name issuer, BigInteger serial) throws OperationFailureException {
		if (serial.equals(goodSerial)) {
			try {
				return Collections.singletonList(generateCertificate(pubKey, name, issuer, serial));
			} catch (Exception e) {
				throw new OperationFailureException(FailInfo.badCertId);
			}
		}
		throw new OperationFailureException(FailInfo.badCertId);
	}

	@Override
	protected List<X509Certificate> doGetCertInitial(X509Name issuer, X509Name subject) throws OperationFailureException {
		if (subject.equals(pollName)) {
			return Collections.<X509Certificate>emptyList();
		}
		try {
			return Collections.singletonList(generateCertificate(pubKey, subject, issuer, goodSerial));
		} catch (Exception e) {
			throw new OperationFailureException(FailInfo.badCertId);
		}
	}

	@Override
	protected List<X509Certificate> getNextCaCertificate(String identifier) {
		if (identifier == null || identifier.isEmpty()) {
			return Collections.singletonList(ca);
		}
		return Collections.<X509Certificate>emptyList();
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
