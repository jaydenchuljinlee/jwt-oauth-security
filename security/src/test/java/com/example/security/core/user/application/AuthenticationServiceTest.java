package com.example.security.core.user.application;

import com.example.security.comn.utils.PasswordEncoder;
import com.example.security.core.auth.application.AuthenticationService;
import com.example.security.core.user.domain.entity.Gender;
import com.example.security.core.user.domain.entity.UserDetail;
import com.example.security.core.user.domain.repository.UserDetailRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {
    @InjectMocks
    AuthenticationService authenticationService;

    @Mock
    UserDetailRepository userDetailRepository;
    @Mock
    PasswordEncoder passwordEncoder;

    @Test
    public void 이메일_패스워드를_인증한다() {
        String email = "ironjin92@gmail.com";
        String password = "Passw@rd123";

        UserDetail user = UserDetail.builder()
                .email("ironjin92@gmail.com")
                .encodedPassword("Passw@rd123")
                .userName("cheoljin")
                .phoneNumber("01012341234")
                .gender(Gender.MALE)
                .build();

        // given
        given(userDetailRepository.findByEmail(email)).willReturn(
                Optional.of(user)
        );

        given(passwordEncoder.matches(password, "Passw@rd123")).willReturn(true);

        // when & then
        UserDetail result = user;

        assertThat(authenticationService.authenticate(email, password)).isEqualTo(result);
    }
}
