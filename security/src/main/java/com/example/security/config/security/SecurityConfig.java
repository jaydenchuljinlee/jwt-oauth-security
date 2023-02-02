package com.example.security.config.security;

import com.example.security.comn.response.BaseResponse;
import com.example.security.config.security.filter.JwtTokenFilterFactory;
import com.example.security.config.security.handler.oauth.OAuth2AuthenticationSuccessHandler;
import com.example.security.core.user.application.CustomOAuth2UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private final JwtTokenFilterFactory jwtTokenFilterFactory;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final Environment environment;

    @Bean
    public WebSecurityCustomizer configure() throws Exception{
        String[] activeProfiles =  environment.getActiveProfiles();

        return (web) -> {
            for (String activeProfile: activeProfiles) {
                web.debug(true);
            }
        };
    }

    @Bean
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(
                        "/auth/login",
                        "/users",
                        "/oauth2/**"
                ).permitAll()
                .anyRequest().authenticated()

                .and()
//                .exceptionHandling()
//                .authenticationEntryPoint(((request, response, authException) -> {
//                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//                    response.setStatus(HttpStatus.FORBIDDEN.value());
//                    response.getWriter().println(
//                            new ObjectMapper().writeValueAsString(BaseResponse.fail(authException.getMessage()))
//                    );
//                }))
//                .and()
                .logout().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .addFilterBefore(jwtTokenFilterFactory.getInstance(), UsernamePasswordAuthenticationFilter.class)
                .oauth2Login()
                .userInfoEndpoint().userService(customOAuth2UserService).and()
                .successHandler(oAuth2AuthenticationSuccessHandler);

        return http.build();
    }
}
