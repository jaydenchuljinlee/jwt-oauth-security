package com.example.security.core.user.infrastructure.jpa;

import com.example.security.core.user.domain.entity.UserDetail;
import com.example.security.core.user.domain.exceptions.UserRepositoryIntegrationException;
import com.example.security.core.user.domain.repository.UserDetailRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.function.Supplier;

@Repository
@RequiredArgsConstructor
public class JpaUserDetailRepository implements UserDetailRepository {
    private final InnerUserDetailRepository repository;

    private <T> T wrapIntegrationException(Supplier<T> process) {
        try {
            return process.get();
        } catch (Exception e) {
            throw new UserRepositoryIntegrationException(e);
        }

    }

    @Override
    public UserDetail save(UserDetail userDetail) {
        return this.wrapIntegrationException(
                () -> this.repository.save(userDetail)
        );
    }

    @Override
    public Optional<UserDetail> findByEmail(String email) {
        return this.wrapIntegrationException(
                () -> this.repository.findByEmail(email)
        );
    }

    @Override
    public boolean existsByEmail(String email) {
        return this.wrapIntegrationException(
                () -> this.repository.existsByEmail(email)
        );
    }

    @Override
    public Optional<UserDetail> findById(long userId) {
        return this.repository.findById(userId);
    }
}
