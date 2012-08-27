package org.jscep.transport.request;

/**
 * This interface represents a SCEP request.
 * <p/>
 * Once an instance of a <code>Request</code> implementation has been obtained,
 * it can be sent to a SCEP server by using an instance of
 * {@link org.jscep.transport.Transport}.
 * 
 * @see org.jscep.transport.Transport#sendRequest(Request,
 *      org.jscep.transport.response.ScepResponseHandler)
 */
public abstract class Request {
    private final Operation operation;

    /**
     * Constructs a new <tt>Request</tt> for the given SCEP <tt>Operation</tt>
     * 
     * @param operation the operation to carry out.
     */
    public Request(Operation operation) {
	this.operation = operation;
    }

    /**
     * Returns the name of this operation.
     * 
     * @return the name of this operation.
     */
    public final Operation getOperation() {
	return operation;
    }

    /**
     * Returns the message for this request.
     * 
     * @return the message.
     */
    public abstract String getMessage();
}
