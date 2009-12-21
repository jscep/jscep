/*
 * Copyright (c) 2009 David Grant
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
import java.io.Writer;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.code.jscep.request.Operation;
import com.google.code.jscep.response.Capabilities;

public abstract class ScepServlet extends HttpServlet {
	private static final Logger LOGGER = Logger.getLogger(ScepServlet.class.getName());
	/**
	 * Serialization ID
	 */
	private static final long serialVersionUID = 1L;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
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
			if (reqMethod.equals("POST") == false && reqMethod.equals("GET") == false) {
				// PKIOperation must be sent using GET or POST
			
				res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
				res.addHeader("Allow", "GET, POST");
				
				return;
			}
		} else {
			if (reqMethod.equals("GET") == false) {
				// Operations other than PKIOperation must be sent using GET
				
				res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
				res.addHeader("Allow", "GET");
				
				return;
			}
		}
		
		LOGGER.fine("Method " + reqMethod + " Allowed for Operation: " + op);
		
		if (op == Operation.GetCACaps) {
			getCapabilities(req.getParameter("message"));
		} else if (op == Operation.GetCACert) {
			getCACertificate(req.getParameter("message"));
		} else if (op == Operation.GetNextCACert) {
			getNextCACertificate(req.getParameter("message"));
		} else {
//			final ServletInputStream is = req.getInputStream();
//			SignedData sd = new SignedData();
		}
	}
	
	abstract protected Capabilities getCapabilities(String identifier);
	abstract protected List<X509Certificate> getCACertificate(String identifier);
	abstract protected List<X509Certificate> getNextCACertificate(String identifier);
	abstract protected X509Certificate getCertificate(X500Principal issuer, BigInteger serial);
	abstract protected X509Certificate getCertificate(X500Principal issuer, X500Principal subject);
	abstract protected List<X509CRL> getCRL(X500Principal issuer, BigInteger serial);
	abstract protected List<X509Certificate> enrollCertificate(byte[] certificationRequest);
	
	private Operation getOperation(HttpServletRequest req) {
		String op = req.getParameter("operation");
		if (op == null)
		{
			return null;
		}
		return Operation.valueOf(req.getParameter("operation"));
	}
}
