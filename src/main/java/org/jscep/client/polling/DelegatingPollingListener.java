package org.jscep.client.polling;

import org.jscep.transaction.TransactionId;

/**
 * This PollingListener delegates to each polling listener until one returns
 * false.
 * <p>
 * Implementors are recommended to order the listeners passed to the constructor
 * with non-blocking listeners first, to avoid unnecessary blocking.
 * <p>
 * For example:
 * 
 * <pre>
 * PollingListener nonBlocking = new CountingPollingListener(5);
 * PollingListener blocking = new BackingOffPollingListener(10L, TimeUnit.SECONDS);
 * new DelegatingPollingListener(nonBlocking, blocking);
 * </pre>
 */
public final class DelegatingPollingListener implements PollingListener {
    private final PollingListener[] listeners;

    /**
     * Creates a new instance with the given delegate PollingListeners.
     * <p>
     * If no listeners are added, this method will delegate to
     * NoPollPollingListener.
     * 
     * @param listeners the listeners to delegate to.
     */
    public DelegatingPollingListener(final PollingListener... listeners) {
        if (listeners == null) {
            this.listeners = new PollingListener[] { new NoPollPollingListener() };
        } else {
            this.listeners = listeners;
        }
    }

    /**
     * Delegates to polling listeners passed in constructor.
     * 
     * {@inheritDoc}
     */
    public boolean poll(final TransactionId id) {
        for (PollingListener listener : listeners) {
            if (!listener.poll(id)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Delegates to polling listeners passed in constructor.
     * 
     * {@inheritDoc}
     */
    public void pollingTerminated(final TransactionId id) {
        for (PollingListener listener : listeners) {
            listener.pollingTerminated(id);
        }
    }

}
