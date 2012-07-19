package org.jscep.client.polling;

import static org.junit.Assert.assertFalse;

import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class NoPollPollingListenerTest {
    private PollingListener listener;

    @Before
    public void setUp() {
        listener = new NoPollPollingListener();
    }
    
    @Test
    public void testPoll() {
        assertFalse(listener.poll(TransactionId.createTransactionId()));
    }
    
    @Test
    public void testPollingTerminated() {
        TransactionId id = TransactionId.createTransactionId();

        listener.pollingTerminated(id);
        assertFalse(listener.poll(id));
    }

}
