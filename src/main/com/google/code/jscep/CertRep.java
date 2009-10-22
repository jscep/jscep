package com.google.code.jscep;

public class CertRep
{
    private enum Status
    {
        FAILURE,
        PENDING,
        SUCCESS
    }
    private Status pkiStatus;
}