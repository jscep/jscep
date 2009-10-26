/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.request;

public class GetCACert implements ScepRequest {
    private static final String OPERATION = "GetCACert";
    private String ca;

    public GetCACert() {
    }

    public GetCACert(String ca) {
        this.ca = ca;
    }

    public String getOperation() {
        return OPERATION;
    }

    public String getMessage() {
        return ca;
    }
}
