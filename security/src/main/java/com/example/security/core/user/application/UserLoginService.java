package com.example.security.core.user.application;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.comn.utils.JwtTokenUtil;
import com.example.security.core.auth.application.AuthenticationService;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.domain.exceptions.InvalidTokenException;
import com.example.security.core.auth.dto.LogoutAccessToken;
import com.example.security.core.auth.dto.RefreshToken;
import com.example.security.core.auth.dto.TokenDto;
import com.example.security.view.web.auth.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;

@Service
@RequiredArgsConstructor
@Transactional
public class UserLoginService {
    private final AuthenticationService authenticationService;
    private final TokenService tokenService;

    public TokenDto login(HttpServletRequest request, LoginRequest loginRequest) {

        // List<String> roles = new ArrayList<>(List.of("ROLE_USER"));

        authenticationService.authenticate(loginRequest.getEmail(), loginRequest.getPassword());



        return tokenService.generateToken(loginRequest.getEmail());
    }

    public LogoutAccessToken logout(HttpServletRequest request, TokenDto tokenDto) {
        String token = tokenService.getToken(request, RequestHeaderType.X_AUTH_ACCESS_TOKEN);
        String email = tokenService.getEmail(token);

        return tokenService.processLogout(email, tokenDto);
    }
}
