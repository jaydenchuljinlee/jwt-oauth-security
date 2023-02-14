package com.example.security.core.auth.application;

import com.example.security.comn.enums.request.RequestCookie;
import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.comn.utils.CookieUtils;
import com.example.security.comn.utils.JwtTokenUtil;
import com.example.security.core.auth.dto.RefreshToken;
import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.Cookie;

import static org.mockito.BDDMockito.given;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class TokenServiceTest {
    private final String EMAIL = "ironjin92@gmail.com";

    @InjectMocks
    private TokenService tokenService;

    @Mock
    private JwtTokenUtil jwtTokenUtil;
    @Mock
    private CacheService cacheService;
    @Mock
    private CookieUtils cookieUtils;

    @Test
    public void 토큰을_생성한다() {
        given(jwtTokenUtil.createAccessToken(EMAIL)).willReturn("access");
        given(jwtTokenUtil.createRefreshToken(EMAIL))
                .willReturn(
                        RefreshToken.of(
                                EMAIL,
                                "refresh",
                                456L));

        // when & then
        TokenDto mayResult = TokenDto.of("access", "refresh");

        assertThat(tokenService.generateToken(EMAIL)).isEqualTo(mayResult);

    }

    @Test
    public void 토큰을_재발행한다() throws JsonProcessingException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), "access");
        String accessToken = request.getHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value());

        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(RequestCookie.AUTH_ID.getValue(), "uuid");

        request.setCookies(cookies);

        // given
        given(cookieUtils.getCookie(cookies, RequestCookie.AUTH_ID.getValue())).willReturn("uuid");
        given(cacheService.getAuthToken(
                cookieUtils.getCookie(cookies, RequestCookie.AUTH_ID.getValue())
        ))
                .willReturn(
                        TokenDto.of("access", "refresh"));

        given(jwtTokenUtil.getToken(accessToken)).willReturn("access");

        given(jwtTokenUtil.getExpiredEmail(accessToken)).willReturn("ironjin92@gmail.com");

        given(jwtTokenUtil.createAccessToken(
                jwtTokenUtil.getExpiredEmail(accessToken)
        )).willReturn(
                "newAccess"
        );

        given(jwtTokenUtil.reIssueRefreshToken(
                cacheService.getAuthToken(
                        cookieUtils.getCookie(cookies, RequestCookie.AUTH_ID.getValue())).getRefreshToken()
        )).willReturn("newRefresh");


        // when & then
        TokenDto result = TokenDto.of("newAccess", "newRefresh");

        assertThat(tokenService.reIssue(request)).isEqualTo(result);
    }

    @Test
    public void 이메일을_가져온다() {
        // given
        given(jwtTokenUtil.getEmail("access")).willReturn("ironjin92@gmail.com");

        // when & then
        assertThat(tokenService.getEmail("access")).isEqualTo("ironjin92@gmail.com");
    }

    @Test
    public void 토큰을_가져온다() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), "access");

        // given
        given(jwtTokenUtil.getToken(request.getHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value()))).willReturn("access");

        // when & then
        assertThat(tokenService.getToken(request, RequestHeaderType.X_AUTH_ACCESS_TOKEN)).isEqualTo("access");
    }
}
