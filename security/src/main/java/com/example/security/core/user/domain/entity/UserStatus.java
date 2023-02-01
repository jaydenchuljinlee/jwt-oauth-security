package com.example.security.core.user.domain.entity;

public enum UserStatus {
    GUEST("손님"),
    NORMAL("정상회원"),
    ASK("탈퇴요청"),
    DROPOUT("탈퇴");

    UserStatus(String desc) {
    }
}
