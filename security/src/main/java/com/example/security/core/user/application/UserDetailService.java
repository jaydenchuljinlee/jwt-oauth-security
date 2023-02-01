package com.example.security.core.user.application;

import com.example.security.core.user.domain.entity.UserDetail;
import com.example.security.core.user.domain.repository.UserDetailRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserDetailService implements UserDetailsService {
    private final UserDetailRepository userDetailRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserDetail> userDetailOptional = userDetailRepository.findByEmail(username);

        if (userDetailOptional.isEmpty()) {
            throw new UsernameNotFoundException(username);
        }

        return userDetailOptional.get();
    }
}
