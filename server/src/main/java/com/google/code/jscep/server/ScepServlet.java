/*
 * Copyright (c) 2009-2010 David Grant
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

package com.google.code.jscep.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.google.code.jscep.asn1.IssuerAndSubject;
import com.google.code.jscep.pkcs7.MessageData;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.pkcs7.PkiMessageParser;
import com.google.code.jscep.pkcs7.SignedDataGenerator;
import com.google.code.jscep.request.Operation;
import com.google.code.jscep.response.Capability;
import com.google.code.jscep.transaction.MessageType;
import com.google.code.jscep.util.LoggingUtil;

public abstract class ScepServlet extends HttpServlet {
	private final static String GET = "GET";
	private final static String POST = "POST";
	private final static String MSG_PARAM = "message";
	private final static String OP_PARAM = "operation";
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep");
	/**
	 * Serialization ID
	 */
	private static final long serialVersionUID = 1L;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
		LOGGER.entering(getClass().getName(), "service");
		
		final Operation op;
		try {
			op = getOperation(req);
			if (op == null) {
				// The operation parameter must be set.
				
				res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				Writer writer = res.getWriter();
				writer.write("Missing \"operation\" parameter.");
				writer.flush();
			
				return;
			}
		} catch (IllegalArgumentException e) {
			// The operation was not recognised.
			
			res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			Writer writer = res.getWriter();
			writer.write("Invalid \"operation\" parameter.");
			writer.flush();
		
			return;
		}
		
		LOGGER.fine("Incoming Operation: " + op);
		
		final String reqMethod = req.getMethod();
			
		if (op == Operation.PKIOperation) {
			if (reqMethod.equals(POST) == false && reqMethod.equals("GET") == false) {
				// PKIOperation must be sent using GET or POST
			
				res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
				res.addHeader("Allow", GET + ", " + POST);
				
				return;
			}
		} else {
			if (reqMethod.equals(GET) == false) {
				// Operations other than PKIOperation must be sent using GET
				
				res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
				res.addHeader("Allow", GET);
				
				return;
			}
		}
		
		LOGGER.fine("Method " + reqMethod + " Allowed for Operation: " + op);
		
		if (op == Operation.GetCACaps) {
			doGetCACaps(req, res);
		} else if (op == Operation.GetCACert) {
			doGetCACert(req, res);
		} else if (op == Operation.GetNextCACert) {
			doGetNextCACert(req, res);
		} else {
			res.setHeader("Content-Type", "application/x-pki-message");
			PkiMessageParser msgParser = new PkiMessageParser();
			PkiMessage msg = msgParser.parse(getBytes(req.getInputStream()));
			
			MessageType msgType = msg.getMessageType();
			MessageData msgData = msg.getPkcsPkiEnvelope().getMessageData();
			if (msgType == MessageType.GetCert) {
				final ASN1Sequence seq = (ASN1Sequence) msgData.getContent();
				final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(seq);
				final X509Name principal = iasn.getName();
				final BigInteger serial = iasn.getCertificateSerialNumber().getValue();

				final X509Certificate cert = getCertificate(principal, serial);
			} else if (msgType == MessageType.GetCertInitial) {
				final ASN1Sequence seq = (ASN1Sequence) msgData.getContent();
				final IssuerAndSubject ias = new IssuerAndSubject(seq);
				final X509Name issuer = ias.getIssuer();
				final X509Name subject = ias.getSubject();
				
				final X509Certificate cert = getCertificate(issuer, subject);
				final SignedDataGenerator generator = new SignedDataGenerator();
				generator.addCertificate(cert);
				final SignedData signedData = generator.generate();
				res.getOutputStream().write(signedData.getDEREncoded());
			} else if (msgType == MessageType.GetCRL) {
				final ASN1Sequence seq = (ASN1Sequence) msgData.getContent();
				final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(seq);
				final X500Principal principal = new X500Principal(iasn.getName().getDEREncoded());
				
				final X509CRL crl = getCRL(principal, iasn.getCertificateSerialNumber().getValue());
				final SignedDataGenerator generator = new SignedDataGenerator();
				generator.addCRL(crl);
				final SignedData signedData = generator.generate();
				res.getOutputStream().write(signedData.getDEREncoded());
			} else if (msgType == MessageType.PKCSReq) {
				final PKCS10CertificationRequest certReq = (PKCS10CertificationRequest) msgData.getContent();
				final List<X509Certificate> certs = enrollCertificate(certReq);
			}
		}
		LOGGER.exiting(getClass().getName(), "service");
	}

	private void doGetNextCACert(HttpServletRequest req, HttpServletResponse res) {
		res.setHeader("Content-Type", "application/x-x509-next-ca-cert");
		
		final List<X509Certificate> certs = getNextCACertificate(req.getParameter(MSG_PARAM));
	}

	private void doGetCACert(HttpServletRequest req, HttpServletResponse res) {
		final List<X509Certificate> certs = getCACertificate(req.getParameter(MSG_PARAM));
		if (certs.size() == 1) {
			res.setHeader("Content-Type", "application/x-x509-ca-cert");
		} else {
			res.setHeader("Content-Type", "application/x-x509-ca-ra-cert");
		}
	}
	
	private byte[] getBytes(InputStream in) {
		return new byte[0];
	}
	
	private Operation getOperation(HttpServletRequest req) {
		String op = req.getParameter(OP_PARAM);
		if (op == null)
		{
			return null;
		}
		return Operation.valueOf(req.getParameter(OP_PARAM));
	}
	
	private void doGetCACaps(HttpServletRequest req, HttpServletResponse res) throws IOException {
		res.setHeader("Content-Type", "text/plain");
		final Set<Capability> caps = getCapabilities(req.getParameter("message"));
		for (Capability cap : caps) {
			res.getWriter().write(cap.toString());
			res.getWriter().write('\n');
		}
		res.getWriter().close();
	}
	
	/**
	 * Returns the capabilities of the specified CA.
	 * 
	 * @param identifier the CA.
	 * @return the capabilities.
	 */
	abstract protected Set<Capability> getCapabilities(String identifier);
	/**
	 * Returns the certificate of the specified CA.
	 * 
	 * @param identifier the CA.
	 * @return the CA's certificate.
	 */
	abstract protected List<X509Certificate> getCACertificate(String identifier);
	/**
	 * Return the next X.509 certificate which will be used by
	 * the specified CA.
	 * 
	 * @param identifier the CA. 
	 * @return the list of certificates.
	 */
	abstract protected List<X509Certificate> getNextCACertificate(String identifier);
	/**
	 * Retrieve the certificate identified by the given parameters.
	 * 
	 * @param issuer the issuer name.
	 * @param serial the serial number.
	 * @return the identified certificate, if any.
	 */
	abstract protected X509Certificate getCertificate(X509Name issuer, BigInteger serial);
	/**
	 * Get Cert Initial
	 * 
	 * @param issuer the issuer name.
	 * @param subject the subject name.
	 * @return the identified certificate, if any.
	 */
	abstract protected X509Certificate getCertificate(X509Name issuer, X509Name subject);
	/**
	 * Retrieve the CRL covering the given certificate identifiers.
	 * 
	 * @param issuer the certificate issuer.
	 * @param serial the certificate serial number.
	 * @return the CRL.
	 */
	abstract protected X509CRL getCRL(X500Principal issuer, BigInteger serial);
	/**
	 * Enroll a certificate into the PKI
	 * 
	 * @param certificationRequest the PKCS #10 CertificationRequest
	 * @return the certificate chain.
	 */
	abstract protected List<X509Certificate> enrollCertificate(PKCS10CertificationRequest certificationRequest);
	abstract protected PrivateKey getPrivate();
}
