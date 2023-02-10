package com.example.security.config.security.handler.oauth;

import com.example.security.comn.service.cache.CacheService;
import com.example.security.config.security.handler.AbstractLoginSuccessHandler;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.dto.TokenDto;
import com.example.security.core.user.domain.dto.KakaoOauth2User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class OAuth2AuthenticationSuccessHandler extends AbstractLoginSuccessHandler {
    private final TokenService tokenService;

    public OAuth2AuthenticationSuccessHandler(CacheService cacheService, TokenService tokenService) {
        super(cacheService);
        this.tokenService = tokenService;
    }

    @Override
    protected TokenDto getTokenDto(Authentication authentication) {
        KakaoOauth2User oauth2User = (KakaoOauth2User) authentication.getPrincipal();

        return tokenService.generateToken(oauth2User.getEmail());
    }

    @Override
    protected void doProcess() {

    }
}
