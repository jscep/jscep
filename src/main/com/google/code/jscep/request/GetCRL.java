/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.request;

public class GetCRL extends AbstractPkiRequest {
    public String getMessage() {
        return null;
    }

    public int getMessageType() {
        return 22;
    }
}
