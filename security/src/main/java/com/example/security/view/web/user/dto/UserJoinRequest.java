package com.example.security.view.web.user.dto;

import com.example.security.comn.validation.user.annotation.*;
import com.example.security.core.user.domain.entity.Gender;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class UserJoinRequest {
    @NotBlank
    @EmailFormat
    private String email;

    @NotBlank
    @UserPasswordFormat
    @JsonProperty("password")
    private String password;

    @NotBlank
    @UserNameForamt
    @JsonProperty("name")
    private String name;

    @NotBlank
    @PhoneNumberFormat
    @JsonProperty("phoneNumber")
    private String phoneNumber;

    @EnumFormat(nullable = true, enumClass = Gender.class)
    @JsonProperty("gender")
    private String gender;

    public Gender genderEnumOrNull() {
        if (gender == null) {
            return null;
        }

        return Gender.valueOf(this.gender);
    }
}
