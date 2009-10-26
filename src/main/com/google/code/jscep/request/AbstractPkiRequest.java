/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.request;

abstract class AbstractPkiRequest implements ScepRequest {
    private static final String OPERATION = "PKIOperation";

    public final String getOperation() {
        return OPERATION;
    }

    abstract int getMessageType();
}
