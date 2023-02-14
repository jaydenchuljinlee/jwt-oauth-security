package com.example.security.core.auth.dto;

import lombok.*;

@EqualsAndHashCode
@Getter @Builder
@AllArgsConstructor @NoArgsConstructor
public class TokenDto {
    private static final int TOKEN_STRING_LOCATION = 7;

    private String accessToken;
    private String refreshToken;

    public static TokenDto of(String accessToken, String refreshToken) {
        return TokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
