package org.jscep.client.polling;

import java.util.concurrent.ConcurrentHashMap;

import org.jscep.transaction.TransactionId;

/**
 * This PollingListener will poll until the number of retries is exceeded.
 */
public class CountingPollingListener implements PollingListener {
    private final int retries;
    private final ConcurrentHashMap<TransactionId, Integer> transAttempts;

    /**
     * Creates a new instance of CountingPollingListener with the given number
     * of retries.
     * 
     * @param retries the number of retries.
     */
    public CountingPollingListener(final int retries) {
        this.retries = retries;
        this.transAttempts = new ConcurrentHashMap<TransactionId, Integer>();
    }

    /**
     * {@inheritDoc}
     */
    public synchronized boolean poll(final TransactionId id) {
        transAttempts.putIfAbsent(id, 1);

        int attempts = transAttempts.get(id);

        if (attempts > retries) {
            return false;
        }

        transAttempts.put(id, ++attempts);

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized void pollingTerminated(TransactionId id) {
        transAttempts.remove(id);
    }

}
