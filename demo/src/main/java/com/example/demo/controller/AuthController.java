package com.example.demo.controller;

import com.example.demo.util.JwtUtil;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/oauth2/callback")
public class AuthController {

  private final JwtUtil jwtUtil;
  public AuthController(JwtUtil j) { this.jwtUtil = j; }

  @GetMapping("/kakao")
  public Map<String, String> kakaoCallback(
      @RequestParam String code) {
    // 1) code → 카카오 access_token 교환 (HTTP call)
    // 2) 카카오 /v2/user/me 호출 → 사용자 정보 획득
    // 3) 사용자 DB 저장/조회 (repo)
    // 4) jwtUtil.generateToken(...) 호출
    String jwt = jwtUtil.generateToken("사용자ID", List.of("ROLE_USER"));
    return Map.of("accessToken", jwt);
  }



}
