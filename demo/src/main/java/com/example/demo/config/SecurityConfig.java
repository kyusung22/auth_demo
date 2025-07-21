package com.example.demo.config;

import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.filter.JwtAuthenticationFilter;
import com.example.demo.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

@Configuration
public class SecurityConfig {

  // ① 필드 선언
  private final CustomOAuth2UserService customOAuth2UserService;
  private final JwtUtil jwtUtil;

  // ② 생성자 주입
  public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
      JwtUtil jwtUtil) {
    this.customOAuth2UserService = customOAuth2UserService;
    this.jwtUtil = jwtUtil;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())

        // 1) 세션 정책 기본값(STATEFUL)으로 돌려두기
        // .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // 주석 처리하거나 아예 제거하세요.

        .oauth2Login(oauth -> oauth
            .loginPage("/login")  // (선택) 여러분이 만든 로그인 페이지
            .userInfoEndpoint(u -> u.userService(customOAuth2UserService))
        )
        .addFilterAfter(new JwtAuthenticationFilter(jwtUtil),
            OAuth2LoginAuthenticationFilter.class)

        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/protected/**").authenticated()
            .anyRequest().permitAll()
        );
    return http.build();
  }


}
