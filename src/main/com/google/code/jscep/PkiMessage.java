/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep;

public class PkiMessage {
    private final int messageType;

    public PkiMessage(int messageType) {
        this.messageType = messageType;
    }

    public int getMessageType() {
        return messageType;
    }

    public PkiStatus getPkiStatus() {
        return PkiStatus.FAILURE;
    }
}
