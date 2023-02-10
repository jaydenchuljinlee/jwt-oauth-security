package com.example.security.view.web.auth;

import com.example.security.comn.enums.request.RequestHeaderType;
import com.example.security.comn.response.BaseResponse;
import com.example.security.comn.service.cache.CacheService;
import com.example.security.core.auth.application.TokenService;
import com.example.security.core.auth.dto.TokenDto;
import com.example.security.core.user.application.UserLoginService;
import com.example.security.view.web.auth.dto.LoginRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@AllArgsConstructor
@RestController
public class AuthController {
    private final UserLoginService userLoginService;
    private final TokenService tokenService;
    private final CacheService cacheService;

    @PostMapping("/login")
    public ResponseEntity<BaseResponse<TokenDto>> login(HttpServletRequest request, @RequestBody LoginRequest loginRequest) throws JsonProcessingException {
        // Servlet Filter를 통해 Login API 처리가 된다.

        TokenDto tokenDto = userLoginService.login(request, loginRequest);
        String uuid = cacheService.setAuthToken(tokenDto);

        return ResponseEntity
                .ok()
                .header(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), tokenDto.getAccessToken())
                .header("SET-COOKIE", uuid)
                .body(BaseResponse.success(tokenDto));
    }

    @PostMapping("/auth/token/reissue")
    public ResponseEntity<BaseResponse<TokenDto>> reissue(
            HttpServletRequest request
    ) throws JsonProcessingException {
        TokenDto tokenDto = tokenService.reIssue(request);
        String uuid = cacheService.setAuthToken(tokenDto);

        return ResponseEntity
                .ok()
                .header(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value(), tokenDto.getAccessToken())
                .header("SET-COOKIE", uuid)
                .body(BaseResponse.success(tokenDto));
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<BaseResponse<Void>> logout(
            HttpServletRequest request,
            @RequestHeader("X-AUTH-ACCESS-TOKEN") String accessToken,
            @RequestHeader("X-AUTH-REFRESH-TOKEN") String refreshToken
    ) {
        TokenDto tokenDto = TokenDto.of(accessToken, refreshToken);

        //userLoginService.logout(request, tokenDto);
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN.value())
                .body(BaseResponse.success());
    }



    @GetMapping("/ping")
    public ResponseEntity<BaseResponse<Void>> ping() {

        log.debug("test");

        return ResponseEntity.ok(BaseResponse.success());
    }
}
