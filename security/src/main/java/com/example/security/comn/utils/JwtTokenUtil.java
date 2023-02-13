package com.example.security.comn.utils;

import com.example.security.comn.properties.JwtProperties;
import com.example.security.core.auth.domain.exceptions.InvalidTokenException;
import com.example.security.core.auth.dto.RefreshToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtTokenUtil {
    private final JwtProperties jwtProperties;

    // private final Long tokenExpirationHour = 30 * 60 * 1000L;
    private static final String JWT_TOKEN_EXCEPT_STRING = "Bearer ";
    private static final int JWT_TOKEN_STRING_START = 7;

    private static final long ONE_DAY = 1000L * 60 * 60 * 24;
    private static final long ACCESS_TOKEN_EXPIRATION_TIME = 1000L * 60 * 30; // 30분
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = ONE_DAY * 7; // 7일

    public String createAccessToken(String email) {
        return this.generateToken(email, ACCESS_TOKEN_EXPIRATION_TIME);
    }

    public RefreshToken createRefreshToken(String email) {
        String token = this.generateToken(email, REFRESH_TOKEN_EXPIRATION_TIME);

        return RefreshToken.of(email, token, REFRESH_TOKEN_EXPIRATION_TIME);
    }

    public String generateToken(String email, long expiration) {
        Claims claims = Jwts.claims();
        claims.put("email", email);

        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(now.getTime() + expiration))
                .setIssuedAt(now)
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getEmail(String token) {
        Claims claims = extractClaims(token);

        return claims.get("email", String.class);
    }

    public boolean isExpiredToken(String token) {
        Date expiration = extractClaims(token).getExpiration();

        return expiration.before(new Date());
    }

    public String reIssueRefreshToken(String token) {
        if (token == null) {
            throw new InvalidTokenException("Refresh Token not exist");
        }

        if (isExpiredToken(token)) {
            throw new InvalidTokenException("Refresh Token was Expired");
        }

        if (!isPassedByHalfTime(token)) return token;

        String email = getEmail(token);

        return generateToken(email, REFRESH_TOKEN_EXPIRATION_TIME);
    }

    public boolean isPassedByHalfTime(String token) {
        long expiration = extractClaims(token).getExpiration().getTime();
        long now = new Date().getTime();
        long diff = expiration - now;

        return (ONE_DAY*4) > diff ;
    }

    public String getToken(String authorization) {
        if (!(StringUtils.hasText(authorization) && authorization.startsWith(JWT_TOKEN_EXCEPT_STRING))) return null;

        return authorization.substring(JWT_TOKEN_STRING_START);
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getExpiredEmail(String token) {
        Claims claims = null;

        try {
            claims = extractClaims(token);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        }

        return claims.get("email", String.class);
    }

    private Key getSignKey() {
        byte[] keyBytes = jwtProperties.getSecret().getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public long getRemainMilliSeconds(String token) {
        Date expiration = extractClaims(token).getExpiration();
        Date now = new Date();

        return expiration.getTime() - now.getTime();
    }
}
