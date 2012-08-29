package org.jscep.transaction;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class InvalidNonceExceptionTest {
    @Test
    public void testTwoNonceConstructor() {
	Nonce sender = Nonce.nextNonce();
	Nonce recipient = Nonce.nextNonce();
	InvalidNonceException exception = new InvalidNonceException(sender, recipient);
	
	assertThat(exception.getMessage(), is(notNullValue()));
    }
    
    @Test
    public void testSingleNonceConstructor() {
	Nonce sender = Nonce.nextNonce();
	InvalidNonceException exception = new InvalidNonceException(sender);
	
	assertThat(exception.getMessage(), is(notNullValue()));
    }
}
