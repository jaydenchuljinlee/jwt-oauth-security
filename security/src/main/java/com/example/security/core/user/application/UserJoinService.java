package com.example.security.core.user.application;

import com.example.security.comn.utils.PasswordEncoder;
import com.example.security.core.user.domain.entity.Gender;
import com.example.security.core.user.domain.entity.UserDetail;
import com.example.security.core.user.domain.exceptions.UserDuplicationException;
import com.example.security.core.user.domain.repository.UserDetailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserJoinService {
    private final UserDetailRepository userDetailRepository;
    private final PasswordEncoder passwordEncoder;

    public UserDetail join(String email, String password, String name, String phoneNumber, Gender gender) {
        this.validateDuplicatedUser(email);

        String encodedPassword = passwordEncoder.encode(password);
        UserDetail userDetail = UserDetail.builder()
                .email(email)
                .encodedPassword(encodedPassword)
                .userName(name)
                .phoneNumber(phoneNumber)
                .gender(gender).build();

        this.userDetailRepository.save(userDetail);

        return userDetail;
    }

    public Optional<UserDetail> getUser(String email) {
        return this.userDetailRepository.findByEmail(email);
    }

    public void validateDuplicatedUser(String email) {
        boolean userWithEmailExists = this.userDetailRepository.existsByEmail(email);

        if(userWithEmailExists) {
            throw UserDuplicationException.duplicatedEmail(email);
        }
    }
}
