package com.example.security.core.user.domain.exceptions;


import com.example.security.comn.exceptions.ResourceNotFoundException;

public class UserNotFoundException extends ResourceNotFoundException {
    public UserNotFoundException(long userId) {
        super("User with the id not found: " + userId);
    }
}
