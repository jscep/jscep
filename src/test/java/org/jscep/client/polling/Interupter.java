package org.jscep.client.polling;

import java.util.concurrent.TimeUnit;

public class Interupter implements Runnable {
    private final Thread thread;
    private final long duration;
    private final TimeUnit unit;

    /**
     * Creates a new Interupter with a Thread to interupt.
     * 
     * @param thread the Thread to interupt.
     */
    public Interupter(Thread thread, long duration, TimeUnit unit) {
        this.thread = thread;
        this.duration = duration;
        this.unit = unit;
    }

    public void run() {
        try {
            unit.sleep(duration);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        thread.interrupt();
    }

}
