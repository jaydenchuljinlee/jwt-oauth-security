package com.example.security.config.security.filter;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.domain.exceptions.InvalidTokenException;
import com.example.security.core.auth.dto.TokenDto;
import com.example.security.core.user.application.UserDetailService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    private final UserDetailService userDetailService;
    private final TokenService tokenService;
    private final CacheService cacheService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = this.tokenService.getToken(request, RequestHeaderType.X_AUTH_ACCESS_TOKEN);

        String email = null;

        if (StringUtils.isNotBlank(accessToken)) {


            tokenService.checkLogout(accessToken);

            boolean isExpired = tokenService.isExpiredAccessToken(accessToken);

            // email = tokenService.getEmail(accessToken);

            if (isExpired) {
                String refreshToken = null;

                for (Cookie cookie: request.getCookies()) {
                    if (!RequestHeaderType.X_AUTH_REFRESH_TOKEN.value().equals(cookie.getName())) continue;

                    refreshToken = cookie.getValue();
                }

                TokenDto tokenDto = cacheService.getAuthToken(email);

                if (!tokenDto.getRefreshToken().equals(refreshToken)) {
                    throw new InvalidTokenException("Refresh Token is not equals with redis data");
                }

                refreshToken = tokenService.getRefreshToken(refreshToken);

                Cookie cookie = new Cookie(RequestHeaderType.X_AUTH_REFRESH_TOKEN.value(), refreshToken);

                accessToken = tokenService.reIssueAccessToken(email);

                response.setHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), accessToken);
                response.addCookie(cookie);

                cacheService.setAuthToken(email, TokenDto.of(accessToken, refreshToken));
            }

            UserDetails userDetails = userDetailService.loadUserByUsername(email);
            this.setAuthentication(request, userDetails);
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

    }
}
