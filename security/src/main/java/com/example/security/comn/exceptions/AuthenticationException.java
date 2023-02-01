package com.example.security.comn.exceptions;

/**
 * 인증 관련 오류
 * e.g. 인증 실패
 */
public class AuthenticationException extends BaseException{
    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationException(Throwable cause) {
        super(cause);
    }
}
