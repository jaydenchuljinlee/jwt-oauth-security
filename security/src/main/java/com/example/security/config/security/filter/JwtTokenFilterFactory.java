package com.example.security.config.security.filter;

import com.example.security.core.auth.application.TokenService;
import com.example.security.core.user.application.UserDetailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtTokenFilterFactory {
    private final UserDetailService userDetailService;
    private final TokenService tokenService;

    public JwtTokenFilter getInstance() {
        return new JwtTokenFilter(userDetailService, tokenService);
    }
}
