package org.jscep.transaction;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * This class provides support for detecting replay attacks.
 */
public final class NonceQueue {
    private static final int DEFAULT_QUEUE_SIZE = 20;
    private final Map<Nonce, Boolean> backingQueue;

    /**
     * Creates a new <tt>NonceQueue</tt> of the specified default size.
     * 
     * @param size
     *            the size of the queue.
     */
    public NonceQueue() {
	this.backingQueue = new WeakHashMap<Nonce, Boolean>(DEFAULT_QUEUE_SIZE);
    }

    /**
     * Inserts the specified <tt>Nonce</tt> into this queue.
     * 
     * @param nonce
     *            the nonce to add.
     */
    public synchronized void add(final Nonce nonce) {
	backingQueue.put(nonce, Boolean.FALSE);
    }

    /**
     * Checks the queue for the given <tt>Nonce</tt>.
     * 
     * @param nonce
     *            the <tt>Nonce</tt> to check for.
     * @return <tt>true</tt> if the <tt>Nonce</tt> is present, <tt>false</tt> otherwise.
     */
    public synchronized boolean contains(final Nonce nonce) {
	return backingQueue.containsKey(nonce);
    }
}
