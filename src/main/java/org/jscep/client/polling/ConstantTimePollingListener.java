package org.jscep.client.polling;

import java.util.concurrent.TimeUnit;

import org.jscep.transaction.TransactionId;

/**
 * This PollingListener always returns true, blocking between polls for the
 * given duration.
 */
public final class ConstantTimePollingListener implements PollingListener {
    private final long duration;
    private final TimeUnit unit;

    /**
     * Creates a new ConstantTimePollingListener with the given interval.
     * 
     * @param duration
     *            the amount of time
     * @param unit
     *            the time unit
     */
    public ConstantTimePollingListener(final long duration, final TimeUnit unit) {
        this.duration = duration;
        this.unit = unit;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized boolean poll(final TransactionId id) {
        try {
            unit.sleep(duration);
        } catch (InterruptedException e) {
            return true;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized void pollingTerminated(final TransactionId id) {
        // Do nothing
    }

}
