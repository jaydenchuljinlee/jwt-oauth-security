package com.example.security.core.user.infrastructure.jpa;

import com.example.security.core.user.domain.entity.UserDetail;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface InnerUserDetailRepository extends JpaRepository<UserDetail, Long> {
    Optional<UserDetail> findByEmail(String email);

    boolean existsByEmail(String email);
}
