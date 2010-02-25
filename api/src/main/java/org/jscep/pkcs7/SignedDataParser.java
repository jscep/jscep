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
package org.jscep.pkcs7;

import java.io.IOException;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.jscep.util.LoggingUtil;


/**
 * This class parses a ASN1 structure and extracts a degenerate (certificates
 * and CRLs only) {@link org.bouncycastle.asn1.cms.SignedData} instance.
 *  
 * @author David Grant
 */
public class SignedDataParser {
	private static Logger LOGGER = LoggingUtil.getLogger(SignedDataParser.class);

	/**
	 * Parses the provided ASN1 object and extracts a degenerate SignedData
	 * instance.
	 * 
	 * @param signedData the ASN1 object to parse.
	 * @return a new degenerate SignedData instance.
	 * @throws IOException if any I/O error occurs.
	 */
	public SignedData parse(ASN1Encodable signedData) throws IOException {
		LOGGER.entering(getClass().getName(), "parse", signedData);
		
		try {
			ContentInfo ci = ContentInfo.getInstance(signedData);
			ASN1Sequence seq = (ASN1Sequence) ci.getContent();
			final SignedData sd = new SignedData(seq);

			LOGGER.exiting(getClass().getName(), "parse", sd);
			return sd;
		} catch (Exception e) {
			
			LOGGER.throwing(getClass().getName(), "parse", e);
			throw new IOException(e);
		}
	}
}
