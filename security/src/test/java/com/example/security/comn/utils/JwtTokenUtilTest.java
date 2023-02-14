package com.example.security.comn.utils;

import com.example.security.comn.properties.JwtProperties;
import com.example.security.core.auth.dto.RefreshToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtTokenUtil의 테스트")
public class JwtTokenUtilTest {
    private final String EMAIL = "ironjin92@gmail.com";

    private JwtTokenUtil jwtTokenUtil;

    @BeforeEach
    public void beforeEach() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret("youcantrevealthesecretkey1234012300040");
        jwtProperties.setTokenExpirationHour(1480849147370L);

        jwtTokenUtil = new JwtTokenUtil(jwtProperties);
    }

    @Test
    public void 토큰을_생성한다() {
        액세스_토큰을_생성한다();
        리프레시_토큰을_생성한다();
    }

    public String 액세스_토큰을_생성한다() {
        // accessToken 생성
        String accessToken = jwtTokenUtil.createAccessToken(EMAIL);

        Assertions.assertInstanceOf(String.class, accessToken);

        return accessToken;
    }

    public String 리프레시_토큰을_생성한다() {
        // accessToken 생성
        RefreshToken refreshToken = jwtTokenUtil.createRefreshToken(EMAIL);

        assertThat(refreshToken).isInstanceOf(RefreshToken.class);

        return refreshToken.getRefreshToken();
    }

    @Test
    public void 토큰에서_이메일을_가져온다() {
        String accessToken = 액세스_토큰을_생성한다();

        String email = jwtTokenUtil.getEmail(accessToken);

        assertThat(email).isEqualTo(EMAIL);
    }

    @Test
    public void 토큰의_유효기간을_확인한다() {
        토큰_유효기간이_지났다();

        토큰_유효기간이_안지났다();
    }

    @Test
    public void 토큰_유효기간이_지났다() {
        String accessToken = 액세스_토큰을_생성한다();


    }

    @Test
    public void 토큰_유효기간이_안지났다() {
        String accessToken = 액세스_토큰을_생성한다();

        assertThat(jwtTokenUtil.isExpiredToken(accessToken)).isFalse();
    }

    @Test
    public void 리프레시_토큰을_재발행한다() {
        String refreshToken = 리프레시_토큰을_생성한다();

        if (리프레시_토큰_만료시간을_넘어서지_않았다()) return;

        String newRefreshToken = jwtTokenUtil.reIssueRefreshToken(refreshToken);

        assertThat(newRefreshToken).isNotEqualTo(newRefreshToken);
    }

    public boolean 리프레시_토큰_만료시간을_넘어서지_않았다() {
        String refreshToken = 리프레시_토큰을_생성한다();

        assertThat(jwtTokenUtil.isExpiredToken(refreshToken)).isFalse();

        return true;
    }
}
