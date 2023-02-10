package com.example.security.comn.enums.request;

import lombok.Getter;

@Getter
public enum RequestCookie {
    AUTH_ID("AUTH-ID");

    private String value;

    RequestCookie(String value) {
        this.value = value;
    }
}
