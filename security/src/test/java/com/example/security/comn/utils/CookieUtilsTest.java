package com.example.security.comn.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.http.Cookie;

public class CookieUtilsTest {
    private Cookie[] cookies;
    private CookieUtils cookieUtils;

    @BeforeEach
    public void setup() {
        this.cookies = new Cookie[1];
        this.cookieUtils = new CookieUtils();

        cookies[0] = new Cookie("key", "value");
    }

    @Test
    public void 쿠키를_반환한다() {
        String cookie = cookieUtils.getCookie(cookies, "key");

        Assertions.assertEquals(cookie, "value");
    }
}
