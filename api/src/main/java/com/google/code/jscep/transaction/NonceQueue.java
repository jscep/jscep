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
 * 
 * @author davidjgrant1978
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
	 * nonce first, so this method will always return true.
	 */
	public boolean offer(Nonce nonce) {
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
