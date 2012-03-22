package org.jscep.transaction;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Iterator;

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
	public void testSize() {
		Assert.assertSame(SIZE, queue.size());
	}

	@Test
	public void testIterator() {
		final Iterator<Nonce> iter = queue.iterator();
		
		Assert.assertTrue(iter.hasNext());
		Assert.assertEquals(nonce, iter.next());
	}

	@Test
	public void testOffer() {
		Assert.assertTrue(queue.offer(nonce));
		Assert.assertEquals(SIZE, queue.size());
	}

	@Test
	public void testPeek() {
		Assert.assertEquals(nonce, queue.peek());
		Assert.assertEquals(nonce, queue.peek());
	}

	@Test
	public void testPoll() {
		Assert.assertEquals(nonce, queue.poll());
		Assert.assertNull(queue.poll());
	}
	
	@Test
	public void testFixedSize() {
		queue.offer(Nonce.nextNonce());
		queue.offer(Nonce.nextNonce());
		queue.offer(Nonce.nextNonce());
		
		Assert.assertSame(SIZE, queue.size());
	}

}
