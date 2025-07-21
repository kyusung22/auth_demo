package com.example.demo.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.*;

@Component
public class JwtUtil {
  private final Key key;
  private final long expMs;
  public JwtUtil(@Value("${jwt.secret}") String secret,
      @Value("${jwt.expiration}") long expMs) {
    this.key = Keys.hmacShaKeyFor(secret.getBytes());
    this.expMs = expMs;
  }
  public String generateToken(String subject, List<String> roles) {
    return Jwts.builder()
        .setSubject(subject)
        .claim("roles", roles)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + expMs))
        .signWith(key).compact();
  }
  public Claims validateAndGetClaims(String token) {
    return Jwts.parserBuilder().setSigningKey(key).build()
        .parseClaimsJws(token).getBody();
  }
}