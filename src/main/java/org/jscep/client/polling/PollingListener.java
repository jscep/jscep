package org.jscep.client.polling;

import org.jscep.transaction.TransactionId;

/**
 * Listener to control the enrollment polling strategy.
 */
public interface PollingListener {
    /**
     * Indicates whether the client should continue polling for the given
     * transaction.
     * <p>
     * When this method returns <tt>false</tt>, the client will throw a
     * PollingTerminatedException.
     * 
     * @param id the transaction ID
     * @return <tt>true</tt> if the client should poll, <tt>false</tt>
     *         otherwise.
     */
    boolean poll(TransactionId id);

    /**
     * This method is invoked when the client gives up polling.
     * <p>
     * This method can be called in two situations:
     * <ul>
     * <li>onPoll returns false</li>
     * <li>the client receives a failure notification</li>
     * </ul>
     * In the former case, implementations can clean up state before returning
     * false, or wait until the call to this method.
     * 
     * @param id the transaction ID.
     */
    void pollingTerminated(TransactionId id);
}
