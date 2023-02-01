package com.example.security.core.auth.domain.repository;

import com.example.security.core.auth.dto.LogoutAccessToken;
import org.springframework.data.repository.CrudRepository;

public interface LogoutAccessTokenRedisRepository extends CrudRepository<LogoutAccessToken, String> {
}
