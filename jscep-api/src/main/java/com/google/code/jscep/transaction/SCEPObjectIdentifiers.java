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

package com.google.code.jscep.transaction;

import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * Object Identifiers used by SCEP
 * 
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#appendix-A">SCEP Internet-Draft Reference</a>
 */
public interface SCEPObjectIdentifiers {
	/**
	 * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) messageType(2)
	 */
	DERObjectIdentifier messageType = new DERObjectIdentifier("2.16.840.1.113733.1.9.2");
    /**
	 * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) pkiStatus(3)
	 */
    DERObjectIdentifier pkiStatus = new DERObjectIdentifier("2.16.840.1.113733.1.9.3");
    /**
     * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) failInfo(4)
     */
    DERObjectIdentifier failInfo = new DERObjectIdentifier("2.16.840.1.113733.1.9.4");
    /**
     * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) senderNonce(5)
     */
    DERObjectIdentifier senderNonce = new DERObjectIdentifier("2.16.840.1.113733.1.9.5");
    /**
     * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) recipientNonce(6)
     */
    DERObjectIdentifier recipientNonce = new DERObjectIdentifier("2.16.840.1.113733.1.9.6");
    /**
     * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) transId(7)
     */
    DERObjectIdentifier transId = new DERObjectIdentifier("2.16.840.1.113733.1.9.7");
    /**
     * 2 16 US(840) 1 VeriSign(113733) pki(1) attributes(9) pkiStatus(8)
     */
    DERObjectIdentifier extensionReq = new DERObjectIdentifier("2.16.840.1.113733.1.9.8");
}
