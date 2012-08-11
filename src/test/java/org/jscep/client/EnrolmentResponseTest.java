package org.jscep.client;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class EnrolmentResponseTest {
	private TransactionId transId;
	private FailInfo failInfo;
	private CertStore certStore;

	@Before
	public void setUp() {
		transId = TransactionId.createTransactionId();
		failInfo = FailInfo.badAlg;
		certStore = mock(CertStore.class);
	}
	
	@Test
	public void testIsPendingReturnsTrueForPendingResponse() {
		assertTrue(pending().isPending());
	}
	
	@Test
	public void testIsPendingReturnsFalseForFailureResponse() {
		assertFalse(failure().isPending());
	}
	
	@Test
	public void testIsPendingReturnsFalseForSuccessResponse() {
		assertFalse(success().isPending());
	}

	@Test
	public void testIsFailureReturnsFalseForNonFailureResponse() {
		assertFalse(pending().isFailure());
	}
	
	@Test
	public void testIsFailureReturnsTrueForFailureResponse() {
		assertTrue(failure().isFailure());
	}
	
	@Test
	public void testIsSuccessReturnsTrueForSuccessResponse() {
		assertTrue(success().isSuccess());
	}
	
	@Test
	public void testIsSuccessReturnsFalseForNonSuccessResponse() {
		assertFalse(pending().isSuccess());
	}
	
	@Test
	public void testGetTransactionIdReturnsConstructorArgument() {
		assertSame(transId, pending().getTransactionId());
	}
	
	@Test(expected=IllegalStateException.class)
	public void testGetCertStoreForNonSuccessResponseThrowsException() {
		pending().getCertStore();
	}
	
	@Test
	public void testGetCertStoreForSuccessResponseReturnsConstructorArgument() {
		assertSame(certStore, success().getCertStore());
	}
	
	@Test(expected=IllegalStateException.class)
	public void testGetFailInfoForNonFailureResponseThrowsException() {
		pending().getFailInfo();
	}
	
	@Test
	public void testGetFailInfoForFailureResponseReturnsConstructorArgument() {
		assertSame(failInfo, failure().getFailInfo());
	}
	
	private EnrolmentResponse success() {
		return new EnrolmentResponse(transId, certStore);
	}
	
	private EnrolmentResponse pending() {
		return new EnrolmentResponse(transId);
	}

	private EnrolmentResponse failure() {
		EnrolmentResponse response = new EnrolmentResponse(transId, failInfo);
		return response;
	}
}
