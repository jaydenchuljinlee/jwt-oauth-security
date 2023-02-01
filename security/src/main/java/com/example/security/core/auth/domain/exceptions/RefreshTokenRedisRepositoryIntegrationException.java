package com.example.security.core.auth.domain.exceptions;


import com.example.security.comn.exceptions.IntegrationException;

public class RefreshTokenRedisRepositoryIntegrationException extends IntegrationException {
    public RefreshTokenRedisRepositoryIntegrationException(Throwable cause) {
        super(cause);
    }
}
