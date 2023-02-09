package com.example.security.comn.enums.request.redis;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RedisKey {
    AUTH_TOKEN("AUTH_TOKEN");

    private String value;
}
