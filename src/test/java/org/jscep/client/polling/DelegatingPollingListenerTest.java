package org.jscep.client.polling;

import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class DelegatingPollingListenerTest {
    private PollingListener noDelegateslistener;
    private PollingListener oneDelegatelistener;
    private PollingListener delegate;

    @Before
    public void setUp() {
        delegate = mock(PollingListener.class);
        noDelegateslistener = new DelegatingPollingListener();
        oneDelegatelistener = new DelegatingPollingListener(delegate);
    }

    @Test
    public void testPollDelegatesNone() {
        TransactionId id = TransactionId.createTransactionId();
        assertFalse(noDelegateslistener.poll(id));
    }

    @Test
    public void testPollDelegatesNoPoll() {
        TransactionId id = TransactionId.createTransactionId();
        oneDelegatelistener.poll(id);

        verify(delegate).poll(id);
    }

    @Test
    public void testPollDelegatesPoll() {
        TransactionId id = TransactionId.createTransactionId();
        when(delegate.poll(id)).thenReturn(true);

        oneDelegatelistener.poll(id);

        verify(delegate).poll(id);
    }

    @Test
    public void testPollingTerminatedDelegates() {
        TransactionId id = TransactionId.createTransactionId();
        oneDelegatelistener.pollingTerminated(id);

        verify(delegate).pollingTerminated(id);
    }
}
