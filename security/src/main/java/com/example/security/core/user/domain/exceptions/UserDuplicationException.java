package com.example.security.core.user.domain.exceptions;


import com.example.security.comn.exceptions.ResourceDuplicationException;

public class UserDuplicationException extends ResourceDuplicationException {
    private UserDuplicationException(String message) {
        super(message);
    }

    public static UserDuplicationException duplicatedEmail(String email) {
        return new UserDuplicationException("User email is duplicated: " + email);
    }
}
