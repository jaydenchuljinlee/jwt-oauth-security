package com.example.security.config.security.handler;

import com.example.security.comn.enums.request.RequestCookie;
import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.core.auth.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final CacheService cacheService;

    protected abstract TokenDto getTokenDto(Authentication authentication);

    protected abstract void doProcess();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        TokenDto tokenDto = getTokenDto(authentication);

        String uuid = cacheService.setAuthToken(tokenDto);

        response.setHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), tokenDto.getAccessToken());
        response.setHeader("SET-COOKIE", uuid);

        log.info("AccessToken => " + tokenDto.getAccessToken());
        log.info("Cookie => " + uuid);

        doProcess();

        getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080/main");
    }
}
