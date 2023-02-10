package com.example.security.view.web.main;

import com.example.security.comn.enums.request.RequestCookie;
import com.example.security.comn.enums.request.RequestHeaderType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@Slf4j
@RestController
public class MainController {

    @ResponseBody
    @GetMapping("/main")
    public HashMap<String, String> main(HttpServletRequest request, HttpServletResponse response) {
       String accessToken = request.getHeader(RequestHeaderType.X_AUTH_ACCESS_TOKEN.value());
       Cookie[] cookies = request.getCookies();

        log.info(accessToken);

        String value = null;

        for (Cookie cookie: cookies) {
            if (!RequestCookie.AUTH_ID.getValue().equals(cookie.getName())) continue;

            value = cookie.getValue();
        }

        HashMap<String, String> result = new HashMap<>();

        result.put(value, accessToken);

        return result;
    }

    @ResponseBody
    @GetMapping("/passed")
    public String passedLogin() {
        return "login is passed";
    }
}
