package com.example.demo.config;

import com.example.demo.filter.JwtAuthenticationFilter;
import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.service.LawyerDetailsService;
import com.example.demo.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;
import org.springframework.stereotype.Component;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final CustomOAuth2UserService customOAuth2UserService;
  private final JwtUtil jwtUtil;

  public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
      JwtUtil jwtUtil
      ) {
    this.customOAuth2UserService = customOAuth2UserService;
    this.jwtUtil = jwtUtil;
  }

  @Component
  public static class OAuth2JwtSuccessHandler implements AuthenticationSuccessHandler {
    private final OAuth2AuthorizedClientService clientService;
    private final JwtUtil jwtUtil;

    public OAuth2JwtSuccessHandler(OAuth2AuthorizedClientService clientService,
        JwtUtil jwtUtil) {
      this.clientService = clientService;
      this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req,
        HttpServletResponse res,
        Authentication authentication) throws IOException {
      OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
      String regId = oauthToken.getAuthorizedClientRegistrationId();
      String principal = oauthToken.getName();

      // 여기서 소셜 토큰 꺼내기
      OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(regId, principal);
      String socialAccessToken  = client.getAccessToken().getTokenValue();
      String socialRefreshToken = client.getRefreshToken().getTokenValue();

      // 내부 JWT 발급
      String jwt = jwtUtil.generateToken(principal,
          oauthToken.getAuthorities().stream()
              .map(a -> a.getAuthority()).toList());

      // JSON 응답
      res.setStatus(HttpServletResponse.SC_OK);
      res.setContentType(MediaType.APPLICATION_JSON_VALUE);
      res.getWriter().write(
          new ObjectMapper().writeValueAsString(Map.of(
              "accessToken", jwt,
              "socialAccessToken", socialAccessToken,
              "socialRefreshToken", socialRefreshToken
          ))
      );
    }
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http,
      OAuth2JwtSuccessHandler oauth2JwtSuccessHandler,
      LawyerDetailsService lawyerDetailsService) throws Exception {

    // OAuth2 로그인 실패 핸들러
    AuthenticationFailureHandler oauth2FailureHandler = (req, res, ex) ->
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 Login Failed");

    // 로컬 로그인 성공 핸들러 → JWT 발급
    AuthenticationSuccessHandler lawyerLoginSuccessHandler = (req, res, auth) -> {
      String token = jwtUtil.generateToken(auth.getName(), auth.getAuthorities().stream()
          .map(a -> a.getAuthority()).toList());
      res.setContentType("application/json");
      res.getWriter().write("{\"token\": \"" + token + "\"}");
    };

    // 로컬 로그인 실패 핸들러
    AuthenticationFailureHandler lawyerLoginFailureHandler = (req, res, ex) ->
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Lawyer Login Failed");

    // DaoAuthenticationProvider (Lawyer 전용)
    DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
    daoProvider.setUserDetailsService(lawyerDetailsService);
    daoProvider.setPasswordEncoder(passwordEncoder());

    http
        // OAuth2 로그인 설정
        .oauth2Login(oauth -> oauth
            .userInfoEndpoint(u -> u.userService(customOAuth2UserService))
            .successHandler(oauth2JwtSuccessHandler)
            .failureHandler(oauth2FailureHandler)
        )

        // 로컬 로그인 설정 (formLogin)
        .formLogin(form -> form
            .loginProcessingUrl("/auth/login") // POST 요청
            .usernameParameter("username")
            .passwordParameter("password")
            .successHandler(lawyerLoginSuccessHandler)
            .failureHandler(lawyerLoginFailureHandler)
        )

        // 세션 설정 (기존 유지: OAuth2용 state 저장 가능)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

        // 인증 Provider 등록 (Lawyer 전용)
        .authenticationProvider(daoProvider)

        // CSRF 비활성화
        .csrf(csrf -> csrf.disable())

        // JWT 필터: OAuth2 로그인 이후에 추가
        .addFilterAfter(new JwtAuthenticationFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class)

        // URL 접근 제한
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/protected/**").authenticated()
            .requestMatchers("/auth/login", "/auth/signup", "/oauth2/**").permitAll()
            .anyRequest().permitAll()
        );

    return http.build();
  }


  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(
      ClientRegistrationRepository registrations) {
    return new InMemoryOAuth2AuthorizedClientService(registrations);
  }


  // 이 아래로 로컬 로그인 @@@@@@@@@@@@@@@@@@@@@@@

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder() ;
  }

  @Bean
  public DaoAuthenticationProvider lawyerAuthProvider(LawyerDetailsService svc){
    DaoAuthenticationProvider prov = new DaoAuthenticationProvider();
    prov.setUserDetailsService(svc);
    prov.setPasswordEncoder(passwordEncoder());

    return prov;
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

}
