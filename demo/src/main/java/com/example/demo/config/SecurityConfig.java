package com.example.demo.config;

import com.example.demo.filter.JwtAuthenticationFilter;
import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;

@Configuration
public class SecurityConfig {

  private final CustomOAuth2UserService customOAuth2UserService;
  private final JwtUtil jwtUtil;

  public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
      JwtUtil jwtUtil) {
    this.customOAuth2UserService = customOAuth2UserService;
    this.jwtUtil = jwtUtil;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // 성공 시 JWT를 JSON으로 반환
    AuthenticationSuccessHandler successHandler = (HttpServletRequest req,
        HttpServletResponse res,
        Authentication auth) -> {
      String username = auth.getName();
      var roles = auth.getAuthorities().stream()
          .map(a -> a.getAuthority()).toList();
      String token = jwtUtil.generateToken(username, roles);
      res.setStatus(HttpServletResponse.SC_OK);
      res.setContentType("application/json");
      res.getWriter().write(
          Map.of("accessToken", token)
              .toString()
      );
    };

    // 실패 시 401 Unauthorized
    AuthenticationFailureHandler failureHandler = (HttpServletRequest req,
        HttpServletResponse res,
        org.springframework.security.core.AuthenticationException ex) -> {
      res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 Login Failed");
    };

    http
        .oauth2Login(oauth -> oauth
            .userInfoEndpoint(u -> u.userService(customOAuth2UserService))
            .successHandler(successHandler)
            .failureHandler(failureHandler)
        )

        .csrf(csrf -> csrf.disable())
        // OAuth2 로그인 과정에서 세션에 state를 저장하려면 STATEFUL
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

        // JWT 필터: OAuth2Login 뒤에 삽입
        .addFilterAfter(new JwtAuthenticationFilter(jwtUtil),
            OAuth2LoginAuthenticationFilter.class)

        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/protected/**").authenticated()
            .anyRequest().permitAll()
        );

    return http.build();
  }
}
