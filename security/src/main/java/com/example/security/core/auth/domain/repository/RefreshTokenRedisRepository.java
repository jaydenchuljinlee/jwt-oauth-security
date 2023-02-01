package com.example.security.core.auth.domain.repository;

import com.example.security.core.auth.dto.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRedisRepository extends CrudRepository<RefreshToken, String> {
}
