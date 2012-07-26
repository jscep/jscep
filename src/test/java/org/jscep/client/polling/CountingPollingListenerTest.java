package org.jscep.client.polling;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class CountingPollingListenerTest {
    private static final int COUNT = 5;
    private PollingListener listener;

    @Before
    public void setUp() {
        listener = new CountingPollingListener(COUNT);
    }

    @Test
    public void testPoll() {
        TransactionId id = TransactionId.createTransactionId();
        for (int i = 0; i < COUNT; i++) {
            assertTrue(listener.pendingStatus(id));
        }
        assertFalse(listener.pendingStatus(id));
    }

    @Test
    public void testPollingTerminatedResets() {
        TransactionId id = TransactionId.createTransactionId();
        for (int i = 0; i < COUNT; i++) {
            assertTrue(listener.pendingStatus(id));
        }
        listener.pollingTerminated(id);
        for (int i = 0; i < COUNT; i++) {
            assertTrue(listener.pendingStatus(id));
        }
        assertFalse(listener.pendingStatus(id));
    }

}
