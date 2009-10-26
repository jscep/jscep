/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.request;

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 22-Oct-2009
 * Time: 17:29:43
 * To change this template use File | Settings | File Templates.
 */
public class GetNextCaCert implements ScepRequest {
    private static final String OPERATION = "GetNextCaCert";
    private String ca;

    public GetNextCaCert() {
    }

    public GetNextCaCert(String ca) {
        this.ca = ca;
    }

    public String getOperation() {
        return OPERATION;
    }

    public String getMessage() {
        return ca;
    }
}
