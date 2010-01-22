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

package com.google.code.jscep.content;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.code.jscep.response.Capabilities;
import com.google.code.jscep.response.Capability;
import com.google.code.jscep.util.LoggingUtil;

/**
 * This class handles responses to <tt>GetCACaps</tt> requests.
 */
public class CaCapabilitiesContentHandler implements ScepContentHandler<Capabilities> {
	private static Logger LOGGER = LoggingUtil.getLogger("com.google.code.jscep.content");

	/**
	 * {@inheritDoc}
	 */
	public Capabilities getContent(InputStream in, String mimeType) throws IOException {
		LOGGER.entering(getClass().getName(), "getContent", new Object[] {in, mimeType});

		if (mimeType.equals("text/plain") == false) {
			LOGGER.log(Level.WARNING, "capabilities.mime.warning", mimeType);
		}

		final Capabilities caps = new Capabilities();

		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		String capability;
		while ((capability = reader.readLine()) != null) {
			for (Capability enumValue : Capability.values()) {
				if (enumValue.toString().equals(capability)) {
					caps.add(enumValue);
				}
			}
		}
		reader.close();

		LOGGER.exiting(getClass().getName(), "getContent", caps);
		return caps;
	}
}
