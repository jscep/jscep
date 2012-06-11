package org.jscep.transaction;

public class OperationFailureException extends Exception {
    /**
     *
     */
    private static final long serialVersionUID = 326478648151473741L;
    private final FailInfo failInfo;

    public OperationFailureException(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    public FailInfo getFailInfo() {
        return failInfo;
    }
}
