package com.example.security.core.auth.domain.exceptions;


import com.example.security.comn.exceptions.AuthenticationException;

public class AuthenticationFailException extends AuthenticationException {
    public AuthenticationFailException(String message) {
        super(message);
    }

    public AuthenticationFailException(String message, Throwable cause) { super(message, cause); }

    public static AuthenticationFailException userNotRegistered(String email) {
        return new AuthenticationFailException("Authentication failed - User not registered with the email: " + email);
    }

    public static AuthenticationFailException userNotRegistered(String email, Throwable cause) {
        return new AuthenticationFailException("Authentication failed - User not registered with the email: " + email, cause);
    }

    public static AuthenticationFailException passwordNotMatched(String email) {
        return new AuthenticationFailException("Authentication failed - Password is not matched with the email:" + email);
    }
}
