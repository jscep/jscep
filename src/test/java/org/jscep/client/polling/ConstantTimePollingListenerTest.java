package org.jscep.client.polling;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;

import org.jscep.transaction.TransactionId;
import org.junit.Before;
import org.junit.Test;

public class ConstantTimePollingListenerTest {
    private PollingListener listener;
    private static final long HALF_DURATION = 1L;
    private static final long DURATION = 2L;
    private static final TimeUnit UNIT = TimeUnit.SECONDS;

    @Before
    public void setUp() {
        listener = new ConstantTimePollingListener(DURATION, UNIT);
    }

    @Test
    public void testPoll() {
        TransactionId id = TransactionId.createTransactionId();
        long start = System.currentTimeMillis();
        assertTrue(listener.poll(id));
        long end = System.currentTimeMillis();
        double actualDuration = Long.valueOf(end - start).doubleValue();
        double expectedDuration = UNIT.toMillis(DURATION) * 0.95;

        assertTrue(actualDuration >= expectedDuration);
    }

    @Test
    public void testPollInterupt() {
        TransactionId id = TransactionId.createTransactionId();

        Interupter interupter = new Interupter(Thread.currentThread(),
                HALF_DURATION, UNIT);

        Thread t = new Thread(interupter);
        t.start();

        long start = System.currentTimeMillis();
        assertTrue(listener.poll(id));
        long end = System.currentTimeMillis();
        long actualDuration = end - start;
        long expectedDuration = UNIT.toMillis(DURATION);

        assertTrue(actualDuration < expectedDuration);
    }

    @Test
    public void testPollingTerminated() {
        TransactionId id = TransactionId.createTransactionId();

        listener.pollingTerminated(id);
        assertTrue(listener.poll(id));
    }

}
