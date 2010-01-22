package com.google.code.jscep.transaction;

import java.util.AbstractQueue;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;

/**
 * This class provides support for detecting replay attacks.
 * <p>
 * The size of this queue can be altered depending on performance
 * requirements.
 */
public class NonceQueue extends AbstractQueue<Nonce> {
	private final int size;
	private final Queue<Nonce> backingQueue;
	
	/**
	 * Creates a new <tt>NonceQueue</tt> of the specified size.
	 * 
	 * @param size the size of the queue.
	 */
	public NonceQueue(int size) {
		this.size = size;
		this.backingQueue = new LinkedList<Nonce>();
	}
	
	@Override
	public Iterator<Nonce> iterator() {
		return backingQueue.iterator();
	}

	@Override
	public int size() {
		return backingQueue.size();
	}

	/**
	 * Inserts the specified nonce into this queue if possible.
	 * <p>
	 * This queue will maintain a fixed size, pushing out the oldest
	 * nonce first.  If this nonce is already in the queue (a replay)
	 * this method will return false.
	 */
	public boolean offer(Nonce nonce) {
		if (backingQueue.contains(nonce)) {
			return false;
		}
		if (size() == size) {
			backingQueue.poll();
		}
		return backingQueue.offer(nonce);
	}

	/**
	 * {@inheritDoc}
	 */
	public Nonce peek() {
		return backingQueue.peek();
	}

	/**
	 * {@inheritDoc}
	 */
	public Nonce poll() {
		return backingQueue.poll();
	}
}
