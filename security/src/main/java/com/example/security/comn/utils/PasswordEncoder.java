package com.example.security.comn.utils;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordEncoder {
    private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder();

    public String encode(String rawPassword) {
        return this.encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String encodedPassword) {
        return this.encoder.matches(rawPassword, encodedPassword);
    }
}
