package com.example.security.comn.service.cache;

import com.example.security.core.auth.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface CacheService {
    String setAuthToken(TokenDto token) throws JsonProcessingException;

    TokenDto getAuthToken(String email) throws JsonProcessingException;
}
