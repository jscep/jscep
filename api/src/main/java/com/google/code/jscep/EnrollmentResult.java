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

package com.google.code.jscep;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

import com.google.code.jscep.transaction.PkiStatus;

/**
 * This class represents the outcome of a enrolment request.
 */
public class EnrollmentResult {
	private List<X509Certificate> certs;
	private Callable<EnrollmentResult> task;
	private String message;
	private PkiStatus status;

	/**
	 * Create a new instance of this class using the given certificate list.
	 * 
	 * @param certs the certificate list.
	 */
	EnrollmentResult(List<X509Certificate> certs) {
		this.certs = certs;
		this.status = PkiStatus.SUCCESS;
	}
	
	/**
	 * Create a new instance of this class using the given task.
	 * 
	 * @param task the enrolment task.
	 */
	EnrollmentResult(Callable<EnrollmentResult> task) {
		this.task = task;
		this.status = PkiStatus.PENDING;
	}
	
	/**
	 * Creates a new instance of this class using the given failure message.
	 * 
	 * @param message the failure message.
	 */
	EnrollmentResult(String message) {
		this.message = message;
		this.status = PkiStatus.FAILURE;
	}
	
	/**
	 * Returns the certificates returned from the enrolment request.
	 * 
	 * @return the enrolled certificates.
	 */
	public List<X509Certificate> getCertificates() {
		return certs;
	}
	
	/**
	 * Returns the task to be used for re-enrolling. 
	 * 
	 * @return the enrolment task.
	 */
	public Callable<EnrollmentResult> getTask() {
		return task;
	}
	
	/**
	 * Returns the enrolment failure message.
	 * 
	 * @return the message.
	 */
	public String getMessage() {
		return message;
	}
	
	/**
	 * Returns the status of this result.
	 * 
	 * @return the status.
	 */
	public PkiStatus getStatus() {
		return status; 
	}
}
