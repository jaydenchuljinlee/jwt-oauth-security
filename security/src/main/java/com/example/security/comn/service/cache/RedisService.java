package com.example.security.comn.service.cache;

import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;

@RequiredArgsConstructor
@Service
public class RedisService implements CacheService{
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public String setAuthToken(TokenDto token) throws JsonProcessingException {
        String dto = objectMapper.writeValueAsString(token);

        String id = UUID.randomUUID().toString();

        redisTemplate.opsForSet().add(id, dto);

        return id;
    }

    @Override
    public TokenDto getAuthToken(String email) {
        String result = redisTemplate.opsForSet().pop(email);
        TokenDto dto = objectMapper.convertValue(result, TokenDto.class);

        return dto;
    }

    ;
}
