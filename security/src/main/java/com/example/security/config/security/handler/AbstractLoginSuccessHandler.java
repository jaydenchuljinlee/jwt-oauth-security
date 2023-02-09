package com.example.security.config.security.handler;

import com.example.security.comn.service.cache.CacheService;
import com.example.security.core.auth.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@RequiredArgsConstructor
public abstract class AbstractLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final CacheService cacheService;

    protected abstract TokenDto getTokenDto(Authentication authentication);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        TokenDto tokenDto = getTokenDto(authentication);

        String id = UUID.randomUUID().toString();

        cacheService.setAuthToken(id, tokenDto);

        getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080/main?accessToken="
                + tokenDto.getAccessToken()
                + "&refreshToken="
                + tokenDto.getRefreshToken()
                + "&UUID="
                + id);
    }
}
