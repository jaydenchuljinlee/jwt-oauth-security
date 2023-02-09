package com.example.security.comn.service.cache;

import com.example.security.comn.enums.request.redis.RedisKey;
import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;

@RequiredArgsConstructor
@Service
public class RedisService implements CacheService{
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public void setAuthToken(String eamil, TokenDto token) throws JsonProcessingException {
        String dto = objectMapper.writeValueAsString(token);

        redisTemplate.opsForSet().add(eamil, dto);
    }

    @Override
    public TokenDto getAuthToken(String email) {
        return objectMapper.convertValue(redisTemplate.opsForSet().pop(email), TokenDto.class);
    }

    ;
}
