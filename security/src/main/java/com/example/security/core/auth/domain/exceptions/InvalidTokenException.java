package com.example.security.core.auth.domain.exceptions;


import com.example.security.comn.exceptions.AuthenticationException;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
