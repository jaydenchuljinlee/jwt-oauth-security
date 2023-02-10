package com.example.security.config.security.handler.form;

import com.example.security.comn.service.cache.CacheService;
import com.example.security.config.security.handler.AbstractLoginSuccessHandler;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.dto.TokenDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class FormLoginSuccessHandler extends AbstractLoginSuccessHandler {
    private final TokenService tokenService;

    FormLoginSuccessHandler(CacheService cacheService, TokenService tokenService) {
        super(cacheService);
        this.tokenService = tokenService;
    }

    @Override
    protected TokenDto getTokenDto(Authentication authentication) {
        String email =  authentication.getPrincipal().toString();

        return tokenService.generateToken(email);
    }

    @Override
    protected void doProcess() {

    }

}
