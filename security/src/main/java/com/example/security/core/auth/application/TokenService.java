package com.example.security.core.auth.application;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.utils.JwtTokenUtil;
import com.example.security.core.auth.domain.exceptions.InvalidTokenException;
import com.example.security.core.auth.domain.repository.LogoutAccessTokenRedisRepository;
import com.example.security.core.auth.domain.repository.RefreshTokenRedisRepository;
import com.example.security.core.auth.dto.LogoutAccessToken;
import com.example.security.core.auth.dto.RefreshToken;
import com.example.security.core.auth.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtTokenUtil jwtTokenUtil;
    private final LogoutAccessTokenRedisRepository logoutAccessTokenRedisRepository;
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    public TokenDto generateToken(String email) {
        String accessToken = jwtTokenUtil.createAccessToken(email);
        RefreshToken refreshToken = jwtTokenUtil.createRefreshToken(email);

        return TokenDto.of(accessToken, refreshToken.getRefreshToken());
    }

    @CacheEvict(value = "user", key = "#email")
    public LogoutAccessToken processLogout(String email, TokenDto tokenDto) {
        deleteRefreshToken(email);
        LogoutAccessToken logoutAccessToken = jwtTokenUtil.createLogoutToken(email, tokenDto.getAccessToken());

        return logoutAccessToken(logoutAccessToken);
    }

    public void deleteRefreshToken(String email) {
        refreshTokenRedisRepository.deleteById(email);
    }

    public LogoutAccessToken logoutAccessToken(LogoutAccessToken logoutAccessToken) {

        return logoutAccessTokenRedisRepository.save(logoutAccessToken);
    }

//    public RefreshToken getRefreshToken(String email) {
//        Optional<RefreshToken> optional = refreshTokenRedisRepository.findById(email);
//
//        if (optional.isEmpty()) {
//            throw new InvalidTokenException("There is no refresh token");
//        }
//
//        return optional.get();
//    }

    public boolean isExpiredAccessToken(String token) {
        return jwtTokenUtil.isExpiredToken(token);
    }

    public void checkLogout(String accessToken) {
        if (logoutAccessTokenRedisRepository.existsById(accessToken)) {
            throw new InvalidTokenException("Token is already logged out");
        }
    }

    public String getEmail(String token) {

        return jwtTokenUtil.getEmail(token);
    }

    public String getToken(HttpServletRequest request, RequestHeaderType requestHeaderType) {
        String token = request.getHeader(requestHeaderType.value());

        return jwtTokenUtil.getToken(token);
    }

    public String getRefreshToken(String token) {
        return jwtTokenUtil.reIssueRefreshToken(token);
    }

    public String reIssueAccessToken(String email) {
        return jwtTokenUtil.createAccessToken(email);
    }
}
