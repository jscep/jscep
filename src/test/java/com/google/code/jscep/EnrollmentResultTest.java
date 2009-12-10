package com.google.code.jscep;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

import junit.framework.Assert;

import org.easymock.EasyMock;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.google.code.jscep.transaction.PkiStatus;

@RunWith(Parameterized.class)
public class EnrollmentResultTest {
	private EnrollmentResult fixture;
	
	@SuppressWarnings("unchecked")
	@Parameters
	public static Collection<Object[]> getParameters() {
		final List<Object[]> params = new ArrayList<Object[]>();
		
		params.add(new Object[] {new EnrollmentResult(EasyMock.createMock(Callable.class))});
		params.add(new Object[] {new EnrollmentResult("Test")});
		params.add(new Object[] {new EnrollmentResult(new ArrayList<X509Certificate>(0))});
		
		return params;
	}
	
	public EnrollmentResultTest(EnrollmentResult fixture) {
		this.fixture = fixture;
	}
	
	@Test
	public void testGetCertificates() {
		if (fixture.getStatus() == PkiStatus.SUCCESS) {
			Assert.assertNotNull(fixture.getCertificates());
		} else {
			Assert.assertNull(fixture.getCertificates());
		}
	}

	@Test
	public void testGetTask() {
		if (fixture.getStatus() == PkiStatus.PENDING) {
			Assert.assertNotNull(fixture.getTask());
		} else {
			Assert.assertNull(fixture.getTask());
		}
	}

	@Test
	public void testGetMessage() {
		if (fixture.getStatus() == PkiStatus.FAILURE) {
			Assert.assertNotNull(fixture.getMessage());
		} else {
			Assert.assertNull(fixture.getMessage());
		}
	}
}
