package org.jscep.transaction;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class NonceQueueTest {
    private NonceQueue queue;
    private Nonce nonce;

    @Before
    public void setUp() {
	nonce = Nonce.nextNonce();
	queue = new NonceQueue();
	queue.add(nonce);
    }

    @Test
    public void testQueueContainsOriginalNonce() {
	assertThat(queue.contains(nonce), is(true));
    }
}
