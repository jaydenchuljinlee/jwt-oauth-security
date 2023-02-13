package com.example.security.comn.service.cache;

import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class RedisService implements CacheService{
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public String setAuthToken(TokenDto token) throws JsonProcessingException {
        String dto = objectMapper.writeValueAsString(token);

        String id = UUID.randomUUID().toString();

        redisTemplate.opsForValue().set(id, dto);

        return id;
    }

    @Override
    public TokenDto getAuthToken(String id) throws JsonProcessingException {
        String result = redisTemplate.opsForValue().get(id);

        return objectMapper.readValue(result, TokenDto.class);
    }
}
