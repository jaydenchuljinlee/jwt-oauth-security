package com.example.security.comn.enums.request;

public enum RequestHeaderType {
    X_AUTH_ACCESS_TOKEN("X-AUTH-ACCESS-TOKEN"), X_AUTH_REFRESH_TOKEN("X-AUTH-REFRESH-TOKEN");

    private String value;

    RequestHeaderType(String value) {
        this.value = value;
    }

    public String value() { return this.value; }
}
