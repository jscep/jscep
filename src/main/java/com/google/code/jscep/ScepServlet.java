package com.google.code.jscep;

import java.io.IOException;
import java.io.Writer;
import java.util.logging.Logger;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.code.jscep.request.Operation;

public class ScepServlet extends HttpServlet {
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
		
		LOGGER.info("Incoming Operation: " + op);
		
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
		
		LOGGER.info("Method " + reqMethod + " Allowed for Operation: " + op);
		
		if (op == Operation.GetCACaps) {
			
		} else if (op == Operation.GetCACert) {
			
		} else if (op == Operation.GetNextCACert) {
			
		} else {
			final ServletInputStream is = req.getInputStream();
//			SignedData sd = new SignedData();
		}
	}
	
	private Operation getOperation(HttpServletRequest req) {
		String op = req.getParameter("operation");
		if (op == null)
		{
			return null;
		}
		return Operation.valueOf(req.getParameter("operation"));
	}
}
