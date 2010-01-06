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

package com.google.code.jscep;

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

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;

import com.google.code.jscep.asn1.IssuerAndSubject;
import com.google.code.jscep.pkcs7.PkcsPkiEnvelopeParser;
import com.google.code.jscep.pkcs7.PkiMessage;
import com.google.code.jscep.pkcs7.PkiMessageParser;
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
			final Set<Capability> caps = getCapabilities(req.getParameter("message"));
			for (Capability cap : caps) {
				res.getWriter().write(cap.toString());
				res.getWriter().write('\n');
			}
			res.getWriter().close();
		} else if (op == Operation.GetCACert) {
			getCACertificate(req.getParameter(MSG_PARAM));
		} else if (op == Operation.GetNextCACert) {
			getNextCACertificate(req.getParameter(MSG_PARAM));
		} else {
			PkcsPkiEnvelopeParser envParser = new PkcsPkiEnvelopeParser(getPrivate());
			PkiMessageParser msgParser = new PkiMessageParser(envParser);
			PkiMessage msg = msgParser.parse(getBytes(req.getInputStream()));
			
			MessageType msgType = msg.getMessageType();
			byte[] msgData = msg.getPkcsPkiEnvelope().getMessageData();
			if (msgType == MessageType.GetCert) {
				final ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(msgData);
				final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(seq);
				final X500Principal principal = new X500Principal(iasn.getName().getDEREncoded());
				final BigInteger serial = iasn.getCertificateSerialNumber().getValue();

				getCertificate(principal, serial);
			} else if (msgType == MessageType.GetCertInitial) {
				final ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(msgData);
				final IssuerAndSubject ias = new IssuerAndSubject(seq);
				final X500Principal issuer = ias.getIssuer();
				final X500Principal subject = ias.getSubject();
				
				getCertificate(issuer, subject);
			} else if (msgType == MessageType.GetCRL) {
				final ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(msgData);
				final IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(seq);
				final X500Principal principal = new X500Principal(iasn.getName().getDEREncoded());
				
				getCRL(principal, iasn.getCertificateSerialNumber().getValue());
			} else if (msgType == MessageType.PKCSReq) {
				enrollCertificate(msgData);
			}
		}
		LOGGER.exiting(getClass().getName(), "service");
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
	abstract protected X509Certificate getCertificate(X500Principal issuer, BigInteger serial);
	/**
	 * Get Cert Initial
	 * 
	 * @param issuer the issuer name.
	 * @param subject the subject name.
	 * @return the identified certificate, if any.
	 */
	abstract protected X509Certificate getCertificate(X500Principal issuer, X500Principal subject);
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
	abstract protected List<X509Certificate> enrollCertificate(byte[] certificationRequest);
	abstract protected PrivateKey getPrivate();
}
