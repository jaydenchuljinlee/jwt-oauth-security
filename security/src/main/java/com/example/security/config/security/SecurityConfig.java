package com.example.security.config.security;

import com.example.security.config.security.filter.JwtTokenFilterFactory;
import com.example.security.config.security.handler.form.FormLoginSuccessHandler;
import com.example.security.config.security.handler.oauth.OAuth2AuthenticationSuccessHandler;
import com.example.security.core.user.application.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private final JwtTokenFilterFactory jwtTokenFilterFactory;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final FormLoginSuccessHandler formLoginSuccessHandler;
    private final Environment environment;

    @Bean
    public WebSecurityCustomizer configure() throws Exception{
        String[] activeProfiles =  environment.getActiveProfiles();

        return (web) -> {
            for (String activeProfile: activeProfiles) {
                web.debug(true);
            }

//            web.ignoring().antMatchers(
//                    "/main",
//                    "/login",
//                    "/login/**",
//                    "/auth/**",
//                    "/users"
//            );
        };
    }

    @Bean
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()

                .antMatchers(
                       "/main",
                        "/login/**",
                        "/auth/**",
                        "/users"
                ).permitAll()
                .anyRequest().authenticated()

                .and()
                .logout().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and().cors()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .successHandler(formLoginSuccessHandler)

                .and()
                .oauth2Login()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .userInfoEndpoint().userService(customOAuth2UserService)
                .and()

                .and()
                .addFilterBefore(jwtTokenFilterFactory.getInstance(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
