package com.example.security.comn.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component @Getter @Setter
@ConfigurationProperties(prefix = "config.auth")
public class JwtProperties {
    private String secret;

    private long tokenExpirationHour;
}
