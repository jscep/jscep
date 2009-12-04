package com.google.code.jscep;

import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ScepServlet extends HttpServlet {
	private static final Logger LOGGER = Logger.getLogger(ScepServlet.class.getName());
	/**
	 * Serialization ID
	 */
	private static final long serialVersionUID = 1L;
	
	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse res) {
		LOGGER.info("doPost()");
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse res) {
		LOGGER.info("doGet()");
	}
}
