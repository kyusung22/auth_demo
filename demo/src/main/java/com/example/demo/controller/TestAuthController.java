package com.example.demo.controller;

import static org.apache.catalina.manager.StatusTransformer.setContentType;

import com.example.demo.util.JwtUtil;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class TestAuthController {
  private final JwtUtil jwtUtil;
  private final RestTemplate rest = new RestTemplate();

  public TestAuthController(JwtUtil jwtUtil) { this.jwtUtil = jwtUtil; }

  @GetMapping("/test/callback")
  public Map<String,Object> test(
      @RequestParam String code) {
    // 1) 카카오 토큰 교환
    MultiValueMap<String,String> b = new LinkedMultiValueMap<>();
    b.add("grant_type","authorization_code");
    b.add("client_id","8677ac2d5c1133ccaf479330eef0c9ae");
    b.add("client_secret","48aRARa75BuIWfyq8L6Z3LaovQ0s6Rq2");
    b.add("redirect_uri","http://localhost:8080/login/oauth2/code/kakao");
    b.add("code", code);
    Map<?,?> kakao = rest.postForObject(
        "https://kauth.kakao.com/oauth/token",
        new HttpEntity<>(b, new HttpHeaders(){{
          setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }}),
        Map.class
    );

    // 2) 자체 JWT 발급
    String jwt = jwtUtil.generateToken("kakaoUser", List.of("ROLE_USER"), "USER");
    return Map.of(
        "social", kakao,
        "jwt", jwt
    );
  }
}
