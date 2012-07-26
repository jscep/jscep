package org.jscep.client.polling;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;

import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class BackingOffPollingListenerTest {
    private PollingListener listener;
    private static final long HALF_DURATION = 1L;
    private static final long DURATION = 2L;
    private static final TimeUnit UNIT = TimeUnit.SECONDS;

    @Before
    public void setUp() {
        listener = new BackingOffPollingListener(DURATION, UNIT);
    }

    @Test
    public void testPoll() {
        TransactionId id = TransactionId.createTransactionId();
        long start = System.currentTimeMillis();
        assertTrue(listener.pendingStatus(id));
        long mid = System.currentTimeMillis();
        assertTrue(listener.pendingStatus(id));
        long end = System.currentTimeMillis();
        double firstDuration = Long.valueOf(mid - start).doubleValue();
        double secondDuration = Long.valueOf(end - mid).doubleValue();
        double expectedDuration = UNIT.toMillis(DURATION) * 0.95;

        assertTrue(firstDuration >= expectedDuration);
        assertTrue(secondDuration >= expectedDuration * 2);
    }

    @Test
    public void testPollInterupt() {
        TransactionId id = TransactionId.createTransactionId();

        Interupter interupter = new Interupter(Thread.currentThread(),
                HALF_DURATION, UNIT);

        Thread t = new Thread(interupter);
        t.start();

        long start = System.currentTimeMillis();
        assertTrue(listener.pendingStatus(id));
        long end = System.currentTimeMillis();
        double actualDuration = Long.valueOf(end - start).doubleValue();
        double expectedDuration = UNIT.toMillis(DURATION) * 0.95;

        assertTrue(actualDuration < expectedDuration);
    }

    @Test
    public void testPollingTerminated() {
        TransactionId id = TransactionId.createTransactionId();

        listener.pollingTerminated(id);
        assertTrue(listener.pendingStatus(id));
    }

}
