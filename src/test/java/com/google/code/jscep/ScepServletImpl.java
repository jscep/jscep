package com.google.code.jscep;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.response.Capabilities.Capability;
import com.google.code.jscep.util.LoggingUtil;

public class ScepServletImpl extends ScepServlet {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep");
	
	@Override
	protected List<X509Certificate> enrollCertificate(byte[] certificationRequest) {
		 LOGGER.entering(getClass().getName(), "enrollCertificate");
		 
		return null;
	}

	@Override
	protected List<X509Certificate> getCACertificate(String identifier) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected List<X509CRL> getCRL(X500Principal issuer, BigInteger serial) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected Capabilities getCapabilities(String identifier) {
		LOGGER.entering(getClass().getName(), "getCapabilities");
		
		Set<String> caps = new HashSet<String>();
		caps.add(Capability.SHA_1.toString());
		
		LOGGER.exiting(getClass().getName(), "getCapabilities", caps);
		return new Capabilities(caps);
	}

	@Override
	protected X509Certificate getCertificate(X500Principal issuer,
			BigInteger serial) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected X509Certificate getCertificate(X500Principal issuer,
			X500Principal subject) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected List<X509Certificate> getNextCACertificate(String identifier) {
		// TODO Auto-generated method stub
		return null;
	}

}
