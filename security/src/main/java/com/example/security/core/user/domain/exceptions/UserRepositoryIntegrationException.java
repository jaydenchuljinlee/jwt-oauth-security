package com.example.security.core.user.domain.exceptions;

import com.example.security.comn.exceptions.IntegrationException;

public class UserRepositoryIntegrationException extends IntegrationException {
    public UserRepositoryIntegrationException(Throwable cause) {
        super(cause);
    }
}
