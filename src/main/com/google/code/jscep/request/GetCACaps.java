/*
 * Copyright (c) 2009 David Grant.
 */

package com.google.code.jscep.request;

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 22-Oct-2009
 * Time: 17:34:55
 * To change this template use File | Settings | File Templates.
 */
public class GetCACaps implements ScepRequest {
    private static final String OPERATION = "GetCACaps";
    private String ca;

    public GetCACaps() {
    }

    public GetCACaps(String ca)
    {
        this.ca = ca;
    }

    public String getOperation() {
        return OPERATION;
    }

    public String getMessage() {
        return ca;
    }
}
