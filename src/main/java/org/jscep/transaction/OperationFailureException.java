package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * This <tt>Exception</tt> reflects a failure encountered when attempting to
 * perform a SCEP operation.
 */
@Immutable
public class OperationFailureException extends TransactionException {
    private static final long serialVersionUID = 326478648151473741L;
    private final FailInfo failInfo;

    /**
     * Creates a new <tt>OperationFailureException</tt> based on the given
     * <tt>FailInfo</tt>.
     * 
     * @param failInfo
     *            the reason for failure.
     */
    public OperationFailureException(FailInfo failInfo) {
	super("Operation failed due to " + failInfo);
	this.failInfo = failInfo;
    }
    
    /**
     * Returns the <tt>failInfo</tt> that caused this exception.
     * 
     * @return the <tt>failInfo</tt>
     */
    public FailInfo getFailInfo() {
	return failInfo;
    }
}
