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

package com.google.code.jscep.request;

/**
 * This class represents the operation for a given <tt>SCEP</tt> transaction.
 *
 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.1">SCEP Internet-Draft Reference</a>
 */
public enum Operation {
	/**
	 * The operation for <tt>GetCACaps</tt>
	 * 
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#appendix-C.1">SCEP Internet-Draft Reference</a>
	 */
	GetCACaps,
	/**
	 * The operation for <tt>GetCACert</tt>
	 * 
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.1">SCEP Internet-Draft Reference</a>
	 */
	GetCACert,
	/**
	 * The operation for <tt>GetNextCACert</tt>
	 * 
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.6">SCEP Internet-Draft Reference</a>
	 */
	GetNextCACert,
	/**
	 * The operation for <tt>PKCSReq</tt>, <tt>GetCertInitial</tt>, <tt>GetCert</tt>
	 * and <tt>GetCRL</tt>
	 * 
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.2">SCEP Internet-Draft Reference</a>
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.3">SCEP Internet-Draft Reference</a>
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.4">SCEP Internet-Draft Reference</a>
	 * @see <a href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.5">SCEP Internet-Draft Reference</a>
	 */
	PKIOperation
}
