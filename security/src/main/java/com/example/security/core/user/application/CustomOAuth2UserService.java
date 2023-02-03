package com.example.security.core.user.application;

import com.example.security.core.user.domain.dto.KakaoOauth2User;
import com.example.security.core.user.domain.dto.OAuth2Attribute;
import com.example.security.core.user.domain.entity.Gender;
import com.example.security.core.user.domain.entity.UserDetail;
import com.example.security.core.user.domain.repository.UserDetailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.security.AuthProvider;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserJoinService userJoinService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //  1번
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();

        //	2번
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        //	3번
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        log.info("registrationId = {}", registrationId);
        log.info("userNameAttributeName = {}", userNameAttributeName);

        // 4번
        OAuth2Attribute oAuth2Attribute =
                OAuth2Attribute.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        String email = oAuth2Attribute.getEmail();

        Optional<UserDetail> duplicated = userJoinService.getUser(email);

        if (duplicated.isPresent()) {
            return KakaoOauth2User.create(duplicated.get());
        }

        UserDetail user = createUser(oAuth2Attribute);

        return KakaoOauth2User.create(user);
    }

    private UserDetail createUser(OAuth2Attribute attribute) {
        return userJoinService.join(
                attribute.getEmail(),
                "Passw@rd123",
                "iron",
                "01012341234", Gender.MALE);
    }
}
