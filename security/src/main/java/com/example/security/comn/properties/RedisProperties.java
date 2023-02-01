package com.example.security.comn.properties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@RequiredArgsConstructor
@Component
public class RedisProperties {
        @Value("${spring.redis.host}")
        private String host;

        @Value("${spring.redis.port}")
        private int port;
}
