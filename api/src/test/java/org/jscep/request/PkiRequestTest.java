package org.jscep.request;

import java.io.IOException;

import junit.framework.Assert;

import org.bouncycastle.cms.CMSSignedData;
import org.easymock.classextension.EasyMock;
import org.jscep.content.CertRepContentHandler;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class PkiRequestTest {
	private CMSSignedData message;
	private PKCSReq fixture;
	
	@Before
	public void setUp() throws Exception {
		message = EasyMock.createMock(CMSSignedData.class);
		EasyMock.expect(message.getEncoded()).andReturn(new byte[0]).times(2);
		EasyMock.replay(message);
		
		fixture = new PKCSReq(message, new CertRepContentHandler());
	}
	
	@Test
	public void testGetMessage() throws IOException {
		Assert.assertEquals(message.getEncoded(), fixture.getMessage());
	}

	@Test
	public void testGetOperation() {
		Assert.assertEquals(Operation.PKIOperation, fixture.getOperation());
	}
	
	@Test
	public void testContentHandler() {
		Assert.assertNotNull(fixture.getContentHandler());
	}
}
