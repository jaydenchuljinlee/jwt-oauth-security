package com.example.security.core.user.domain.exceptions;


import com.example.security.comn.exceptions.DomainValueException;

public class UserDomainValueException extends DomainValueException {
    public UserDomainValueException(String fieldName, Object value) {
        super("User domain field '" + fieldName + "' doesn't support given value: " + value);
    }
}
