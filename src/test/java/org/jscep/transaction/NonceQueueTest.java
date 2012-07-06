package org.jscep.transaction;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class NonceQueueTest {
    private static final int SIZE = 1;
    private NonceQueue queue;
    private Nonce nonce;

    @Before
    public void setUp() {
        nonce = Nonce.nextNonce();
        queue = new NonceQueue(SIZE);
        queue.add(nonce);
    }

    @Test
    public void testQueueContainsOriginalNonce() {
        assertThat(queue.contains(nonce), is(true));
    }

    @Test
    public void testQueueDoesNotContainsOriginalNonceAfterSizeExceeded() {
        queue.add(Nonce.nextNonce());
        assertThat(queue.contains(nonce), is(false));
    }
}
