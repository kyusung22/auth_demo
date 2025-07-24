package com.example.demo.filter;

import com.example.demo.entity.User;          // 일반 사용자 엔티티
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class UserPrincipal implements UserDetails {

  private final User user;

  // 생성자: User 엔티티만 받습니다.
  public UserPrincipal(User user) {
    this.user = user;
  }

  // == UserDetails 메서드 최소 구현 ==
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    // roles 사용 안 하므로 빈 리스트
    return Collections.emptyList();
  }

  @Override
  public String getPassword() {
    // JWT 인증만 쓰므로 비어 있어도 됩니다.
    return null;
  }

  @Override
  public String getUsername() {
    // subject 로 설정한 ID
    return user.getId().toString();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  // 편의 메서드
  public String getEmail() {
    return user.getEmail();
  }
}