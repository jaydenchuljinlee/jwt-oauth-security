package com.example.security.comn.utils;

import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;

@Component
public class CookieUtils {
    public String getCookie(Cookie[] cookies, String key) {
        String value = null;

        for (Cookie cookie: cookies) {
            if (!key.equals(cookie.getName())) continue;

            value = cookie.getValue();
        }

        return value;
    }

}
