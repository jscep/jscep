package com.google.code.jscep.transaction;

import static org.junit.Assert.fail;

import java.util.Iterator;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class NonceQueueTest {
	private static final int SIZE = 1;
	private NonceQueue queue;
	private Nonce nonce;
	
	@Before
	public void setUp() {
		nonce = NonceFactory.nextNonce();
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
		queue.offer(NonceFactory.nextNonce());
		queue.offer(NonceFactory.nextNonce());
		queue.offer(NonceFactory.nextNonce());
		
		Assert.assertSame(SIZE, queue.size());
	}

}
