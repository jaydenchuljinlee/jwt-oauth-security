package com.example.security.core.auth.application;

import com.example.security.comn.enums.request.RequestCookie;
import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.comn.utils.CookieUtils;
import com.example.security.comn.utils.JwtTokenUtil;
import com.example.security.core.auth.dto.RefreshToken;
import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtTokenUtil jwtTokenUtil;
    private final CacheService cacheService;
    private final CookieUtils cookieUtils;

    public TokenDto generateToken(String email) {
        String accessToken = jwtTokenUtil.createAccessToken(email);
        RefreshToken refreshToken = jwtTokenUtil.createRefreshToken(email);

        return TokenDto.of(accessToken, refreshToken.getRefreshToken());
    }

    public TokenDto reIssue(HttpServletRequest request) throws JsonProcessingException {
        String accessToken = request.getHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value());
        String uuid = cookieUtils.getCookie(request.getCookies(), RequestCookie.AUTH_ID.getValue());

        TokenDto tokenDto = cacheService.getAuthToken(uuid);

        accessToken = jwtTokenUtil.getToken(accessToken);

        if (!accessToken.equals(tokenDto.getAccessToken())) {
            throw new SignatureException("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted");
        }

        String email = jwtTokenUtil.getExpiredEmail(accessToken);

        String newAccessToken = jwtTokenUtil.createAccessToken(email);
        String refreshToken = jwtTokenUtil.reIssueRefreshToken(tokenDto.getRefreshToken());

        return TokenDto.of(newAccessToken, refreshToken);
    }

    public String getEmail(String token) {
        return jwtTokenUtil.getEmail(token);
    }

    public String getToken(HttpServletRequest request, RequestHeaderType requestHeaderType) {
        String token = request.getHeader(requestHeaderType.value());

        return jwtTokenUtil.getToken(token);
    }
}
