package org.jscep.client.polling;

import org.jscep.transaction.TransactionId;

/**
 * PollingListener that doesn't support polling.
 */
public final class NoPollPollingListener implements PollingListener {
    /**
     * Always returns <tt>false</tt>.
     * 
     * {@inheritDoc}
     */
    public boolean poll(final TransactionId id) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void pollingTerminated(final TransactionId id) {
        // Do nothing
    }

}
