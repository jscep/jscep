/*
 * Copyright (c) 2009 David Grant
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
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import com.google.code.jscep.response.Capabilities;

/**
 * This class handles responses to <tt>GetCACaps</tt> requests.
 */
public class CaCapabilitiesContentHandler implements ScepContentHandler<Capabilities> {
	private static Logger LOGGER = Logger.getLogger("com.google.code.jscep.content");
	
	/**
	 * {@inheritDoc}
	 */
    public Capabilities getContent(InputStream in, String mimeType) throws IOException {
		if (mimeType.equals("text/plain") == false) {
			LOGGER.fine("CACapabilities response was of content-type " + mimeType + ".  Expected text/plain");
		}
		
        final List<String> capabilities = new LinkedList<String>();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String capability;
        while ((capability = reader.readLine()) != null) {
        	capabilities.add(capability);
        }
        reader.close();

        return new Capabilities(capabilities);
    }
}
