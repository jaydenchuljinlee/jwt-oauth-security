package com.example.security.view.web.auth.dto;

import com.example.security.comn.validation.user.annotation.EmailFormat;
import com.example.security.comn.validation.user.annotation.UserPasswordFormat;
import lombok.Data;

import javax.validation.constraints.NotNull;

@Data
public class LoginRequest {
    @NotNull
    @EmailFormat
    private String email;

    @NotNull
    @UserPasswordFormat
    private String password;
}
