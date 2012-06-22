/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.transaction;

import java.util.LinkedList;
import java.util.Queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides support for detecting replay attacks.
 * <p/>
 * The size of this queue can be altered depending on performance
 * requirements.
 *
 * @author David Grant
 */
public final class NonceQueue {
    private static final Logger LOGGER = LoggerFactory.getLogger(NonceQueue.class);
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

    /**
     * Inserts the specified nonce into this queue if possible.
     * <p/>
     * This queue will maintain a fixed size, pushing out the oldest
     * nonce first, so this method will always return true.
     */
    public synchronized boolean add(Nonce nonce) {
        if (backingQueue.size() == size) {
            Nonce removedNonce = backingQueue.poll();
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Removed " + removedNonce + " from head of queue.");
            }
        }
        return backingQueue.offer(nonce);
    }

	public synchronized boolean contains(Nonce nonce) {
		return backingQueue.contains(nonce);
	}
}
