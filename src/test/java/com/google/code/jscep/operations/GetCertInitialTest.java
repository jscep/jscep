package com.google.code.jscep.operations;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.code.jscep.asn1.IssuerAndSubject;
import com.google.code.jscep.transaction.MessageType;

public class GetCertInitialTest {
	private PkiMessage fixture;
	private X500Principal issuer;
	private X500Principal subject;
	
	@Before
	public void setUp() {
		issuer = new X500Principal("CN=issuer");
		subject = new X500Principal("CN=subject");
		fixture = new GetCertInitial(issuer, subject);
	}

	@Test
	public void testGetMessageType() {
		Assert.assertSame(MessageType.GetCertInitial, fixture.getMessageType());
	}

	@Test
	public void testGetMessageData() throws IOException, GeneralSecurityException {
		final IssuerAndSubject ias = new IssuerAndSubject(issuer, subject);
		
		Assert.assertArrayEquals(ias.getDEREncoded(), fixture.getMessageData());
	}

}
