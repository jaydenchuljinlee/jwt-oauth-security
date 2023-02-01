package com.example.security.view.web.user.dto;

import com.example.security.core.user.domain.entity.Gender;
import com.example.security.core.user.domain.entity.UserDetail;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@Builder(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class UserJoinResponse {
    @JsonProperty("id")
    private long id;

    @JsonProperty("email")
    private String email;

    @JsonProperty("name")
    private String name;

    @JsonProperty("gender")
    private String gender;

    public static UserJoinResponse of(UserDetail userDetail) {
        Gender gender= userDetail.getGender();
        return UserJoinResponse.builder()
                .id(userDetail.getId())
                .email(userDetail.getEmail())
                .name(userDetail.getName())
                .gender((gender == null) ? null : gender.name())
                .build();
    }
}
