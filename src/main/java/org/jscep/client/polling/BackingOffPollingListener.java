package org.jscep.client.polling;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.jscep.transaction.TransactionId;

/**
 * This PollingListener always returns true, blocking between polls for a
 * duration that doubles on each poll event.
 * <p>
 * For example, if instantiated with one minute, this implementation will block
 * for one minute initially, followed by two minutes, then four minutes, then
 * eight minutes, etc.
 */
public final class BackingOffPollingListener implements PollingListener {
    private final long duration;
    private final TimeUnit unit;
    private final ConcurrentHashMap<TransactionId, Long> transDuration;

    /**
     * Creates a new BackingOffPollingListener with the startng interval.
     * 
     * @param duration the amount of time
     * @param unit the time unit
     */
    public BackingOffPollingListener(final long duration, final TimeUnit unit) {
        this.duration = duration;
        this.unit = unit;
        this.transDuration = new ConcurrentHashMap<TransactionId, Long>();
    }

    /**
     * {@inheritDoc}
     */
    public synchronized boolean poll(final TransactionId id) {
        transDuration.putIfAbsent(id, duration);
        long time = transDuration.get(id);

        try {
            unit.sleep(time);
        } catch (InterruptedException e) {
            return true;
        }

        transDuration.put(id, time * 2);

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized void pollingTerminated(final TransactionId id) {
        transDuration.remove(id);
    }

}
