package com.example.security.comn.exceptions;

public class ResourceDuplicationException extends BaseException{
    public ResourceDuplicationException(String message) {
        super(message);
    }

    public ResourceDuplicationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ResourceDuplicationException(Throwable cause) {
        super(cause);
    }
}
