package com.example.security.core.auth.domain.exceptions;


import com.example.security.comn.exceptions.IntegrationException;

public class LogoutAccessTokenRedisRepositoryIntegrationException extends IntegrationException {
    public LogoutAccessTokenRedisRepositoryIntegrationException(Throwable cause) {
        super(cause);
    }
}
