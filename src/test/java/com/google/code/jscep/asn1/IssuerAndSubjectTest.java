package com.google.code.jscep.asn1;

import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class IssuerAndSubjectTest {
	private IssuerAndSubject fixture;
	private X500Principal issuer;
	private X500Principal subject;
	
	@Before
	public void setUp() {
		issuer = new X500Principal("CN=issuer");
		subject = new X500Principal("CN=subject");
		fixture = new IssuerAndSubject(issuer, subject);
	}
	
	@Test
	public void testGetIssuer() {
		Assert.assertEquals(issuer, fixture.getIssuer());
	}

	@Test
	public void testGetSubject() {
		Assert.assertEquals(subject, fixture.getSubject());
	}
}
