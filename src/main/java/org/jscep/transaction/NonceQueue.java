package org.jscep.transaction;

import java.util.LinkedList;
import java.util.Queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides support for detecting replay attacks.
 * <p/>
 * The size of this queue can be altered depending on memory requirements.
 */
public final class NonceQueue {
    /**
     * The default size for a <tt>NonceQueue</tt>.
     */
    public static final int DEFAULT_QUEUE_SIZE = 20;
    private static final Logger LOGGER = LoggerFactory
	    .getLogger(NonceQueue.class);
    private final int size;
    private final Queue<Nonce> backingQueue;

    /**
     * Creates a new <tt>NonceQueue</tt> of the specified size.
     * 
     * @param size
     *            the size of the queue.
     */
    public NonceQueue(int size) {
	this.size = size;
	this.backingQueue = new LinkedList<Nonce>();
    }

    /**
     * Creates a <tt>NonceQueue</tt> of a default size.
     */
    public NonceQueue() {
	this(DEFAULT_QUEUE_SIZE);
    }

    /**
     * Inserts the specified <tt>Nonce</tt> into this queue.
     * <p/>
     * This queue will maintain a fixed size, pushing out the oldest <tt>Nonce</tt>
     * first.
     * 
     * @param nonce
     *            the nonce to add.
     */
    public synchronized void add(final Nonce nonce) {
	if (backingQueue.size() == size) {
	    Nonce removedNonce = backingQueue.poll();
	    if (LOGGER.isTraceEnabled()) {
		LOGGER.trace("Removed {} from head of queue.", removedNonce);
	    }
	}
	backingQueue.offer(nonce);
    }

    /**
     * Checks the queue for the given <tt>Nonce</tt>.
     * 
     * @param nonce
     *            the <tt>Nonce</tt> to check for.
     * @return <tt>true</tt> if the <tt>Nonce</tt> is present, <tt>false</tt> otherwise.
     */
    public synchronized boolean contains(final Nonce nonce) {
	return backingQueue.contains(nonce);
    }
}
