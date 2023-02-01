package com.example.security.core.user.application;

import com.example.security.comn.enums.request.RequestHeaderType;
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
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationService authenticationService;
    private final TokenService tokenService;

    public TokenDto login(LoginRequest loginRequest) {

        // List<String> roles = new ArrayList<>(List.of("ROLE_USER"));

        authenticationService.authenticate(loginRequest.getEmail(), loginRequest.getPassword());

        String accessToken = jwtTokenUtil.createAccessToken(loginRequest.getEmail());
        RefreshToken refreshToken = tokenService.saveRefreshToken(loginRequest.getEmail());

        return TokenDto.of(accessToken, refreshToken.getRefreshToken());
    }

    public LogoutAccessToken logout(HttpServletRequest request, TokenDto tokenDto) {
        String token = tokenService.getToken(request, RequestHeaderType.X_AUTH_ACCESS_TOKEN);
        String email = tokenService.getEmail(token);

        return tokenService.processLogout(email, tokenDto);
    }

    // TODO 리프레시 토큰 로직 검증 필요
    public TokenDto reissue(String refreshToken) {
        // TODO refreshToken으로 이메일을 가져올 수 있나??
        String email = tokenService.getEmail(refreshToken);
        RefreshToken savedRefreshToken = tokenService.getRefreshToken(email);

        if (!refreshToken.equals(savedRefreshToken.getRefreshToken())) {
            throw new InvalidTokenException("refresh token do not matched");
        }

        return reissueRefreshToken(refreshToken, email);
    }

    private TokenDto reissueRefreshToken(String refreshToken, String email) {
        // TODO refresh token 만료 시간이 지났으면 리프레시 토큰을 재생성 해준다

        String accessToken = jwtTokenUtil.createAccessToken(email);

        if (!jwtTokenUtil.isExpiredToken(refreshToken)) {
            RefreshToken newRefreshToken = jwtTokenUtil.createRefreshToken(email);
            return TokenDto.of(accessToken, newRefreshToken.getRefreshToken());
        }

        // TODO 지나지 않았으면 access token만 발금해준다.
        return TokenDto.of(accessToken, refreshToken);
    }
}
