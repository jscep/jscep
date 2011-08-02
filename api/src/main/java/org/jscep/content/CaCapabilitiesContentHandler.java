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
package org.jscep.content;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.jscep.response.Capabilities;
import org.jscep.response.Capability;
import org.jscep.util.LoggingUtil;
import org.slf4j.Logger;


/**
 * This class handles responses to <code>GetCACaps</code> requests.
 * 
 * @author David Grant
 */
public class CaCapabilitiesContentHandler implements ScepContentHandler<Capabilities> {
	private static Logger LOGGER = LoggingUtil.getLogger(CaCapabilitiesContentHandler.class);

	/**
	 * {@inheritDoc}
	 */
	public Capabilities getContent(InputStream in, String mimeType) throws IOException {
		if (mimeType.startsWith("text/plain") == false) {
			LOGGER.warn("Capabilities is not plain text", mimeType);
		}

		final Capabilities caps = new Capabilities();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Parsing capabilities...");
		}
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		String capability;
		while ((capability = reader.readLine()) != null) {
			for (Capability enumValue : Capability.values()) {
				if (enumValue.toString().equals(capability)) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("SCEP server supports " + enumValue.getDescription());
					}
					caps.add(enumValue);
				}
			}
		}
		reader.close();

		return caps;
	}
}
