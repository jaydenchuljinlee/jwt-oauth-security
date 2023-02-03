package com.example.security.view.web.main;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.core.auth.dto.TokenDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@RestController
public class MainController {
    @ResponseBody
    @GetMapping("/main")
    public TokenDto main(HttpServletRequest request) {
        String accessToken = request.getHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.toString());
        String refreshToken = request.getHeader(RequestHeaderType.X_AUTH_REFRESH_TOKEN.toString());
        return TokenDto.of(accessToken, refreshToken);
    }
}
