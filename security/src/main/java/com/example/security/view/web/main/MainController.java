package com.example.security.view.web.main;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class MainController {

    @ResponseBody
    @GetMapping("/main/{accessToken}")
    public String main(@PathVariable String accessToken) {
        return accessToken;
    }
}
