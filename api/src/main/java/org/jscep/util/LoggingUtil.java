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
package org.jscep.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * This class provides logging facilities.
 * 
 * @author David Grant
 */
public final class LoggingUtil {
	private static Map<String, Logger> cache = new HashMap<String, Logger>();

	/**
	 * Private constructor to prevent instantiation.
	 */
	private LoggingUtil() {
		// This constructor will never be invoked.
	}
	
	/**
	 * Returns a logger for the given class.
	 * 
	 * @param type the logger.
	 * @return a logger for the given class.
	 */
	public static Logger getLogger(Class<?> type) {
		return getLogger(type.getPackage().getName());
	}

	/**
	 * Returns a logger for the given package name.
	 * <p>
	 * This method returns a logger configured with a resource
	 * bundle for the given package.  Loggers are cached, so 
	 * calling this method repeatedly with the same package name
	 * will yield the same logger.
	 * 
	 * @param packageName the package name.
	 * @return a logger for the given package name.
	 */
	public static Logger getLogger(String packageName) {
		if (cache.containsKey(packageName) == false) {
			cache.put(packageName, LoggerFactory.getLogger(packageName));
		}
		
		return cache.get(packageName);
	}
}
