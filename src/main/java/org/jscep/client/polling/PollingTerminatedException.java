package org.jscep.client.polling;

import net.jcip.annotations.Immutable;

@Immutable
public class PollingTerminatedException extends Exception {
    private static final long serialVersionUID = 1L;

    public PollingTerminatedException() {
        super();
    }
}
