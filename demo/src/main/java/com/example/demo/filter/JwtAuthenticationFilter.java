package com.example.demo.filter;


import com.example.demo.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.security.authentication.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.*;
import org.springframework.security.web.authentication.*;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.stream.*;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtUtil jwtUtil;
  public JwtAuthenticationFilter(JwtUtil jwtUtil) { this.jwtUtil = jwtUtil; }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
      FilterChain chain) throws ServletException, IOException {
    String header = req.getHeader("Authorization");
    if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
      String token = header.substring(7);
      try {
        Claims claims = jwtUtil.validateAndGetClaims(token);
        var auth = claims.get("roles", List.class).stream()
            .map(r -> new SimpleGrantedAuthority((String)r))
            .collect(Collectors.toList());
        var authToken = new UsernamePasswordAuthenticationToken(
            auth, claims.getSubject(), null);
        SecurityContextHolder.getContext().setAuthentication(authToken);
      } catch (JwtException ignored) { }
    }
    chain.doFilter(req, res);
  }
}