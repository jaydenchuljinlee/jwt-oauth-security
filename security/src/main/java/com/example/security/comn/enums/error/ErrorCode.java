package com.example.security.comn.enums.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    TOKEN_EXPIRED("TOKEN_EXPIRED", 498);

    private String desc;
    private int code;
}
