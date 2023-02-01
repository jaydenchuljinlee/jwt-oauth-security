package com.example.security.core.user.domain.repository;

import com.example.security.core.user.domain.entity.UserDetail;

import java.util.Optional;

public interface UserDetailRepository {
    UserDetail save(UserDetail userDetail);

    Optional<UserDetail> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<UserDetail> findById(long userId);
}
