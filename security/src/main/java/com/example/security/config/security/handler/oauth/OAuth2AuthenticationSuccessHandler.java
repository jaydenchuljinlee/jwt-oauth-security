package com.example.security.config.security.handler.oauth;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.core.auth.application.AuthenticationService;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.dto.RefreshToken;
import com.example.security.core.auth.dto.TokenDto;
import com.example.security.core.user.domain.dto.KakaoOauth2User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        KakaoOauth2User oauth2User = (KakaoOauth2User) authentication.getPrincipal();

        TokenDto tokenDto = tokenService.generateToken(oauth2User.getEmail());

        response.setHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.toString(), tokenDto.getAccessToken());
        response.setHeader(RequestHeaderType.X_AUTH_REFRESH_TOKEN.toString(), tokenDto.getAccessToken());

        getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080/main");
        // super.onAuthenticationSuccess(request, response, authentication);
    }
}
