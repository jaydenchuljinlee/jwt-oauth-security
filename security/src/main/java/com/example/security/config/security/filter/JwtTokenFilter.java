package com.example.security.config.security.filter;

import com.example.security.comn.enums.error.ErrorCode;
import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.user.application.UserDetailService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    private final UserDetailService userDetailService;
    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = this.tokenService.getToken(request, RequestHeaderType.X_AUTH_ACCESS_TOKEN);

        if (request.getRequestURI().equals("/auth/token/reissue")) {
            filterChain.doFilter(request, response);
            return;
        }

        if (StringUtils.isBlank(accessToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        String email = "";

        try {
            // TODO 토큰이 존재하는지 확인, 만료 예외가 아닌 다른 예외가 발생한다면? ex) 임의의 토큰을 발행한 경우 어떤 예외가 오냐에 따라 401을 던져주자
            email = tokenService.getEmail(accessToken);
        } catch(ExpiredJwtException e) {
            setErrorResponse(response, ErrorCode.TOKEN_EXPIRED.getCode());
        } catch(SignatureException e) {
            setErrorResponse(response, HttpStatus.UNAUTHORIZED.value());
        }

        if (StringUtils.isNotEmpty(email)) {
            UserDetails userDetails = userDetailService.loadUserByUsername(email);
            this.setAuthentication(request, userDetails);

            filterChain.doFilter(request, response);
        }
    }

    private void setErrorResponse(HttpServletResponse response, int code) {
        response.setStatus(code);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }


    private void setAuthentication(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

    }
}
