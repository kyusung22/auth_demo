package com.example.demo.filter;

import com.example.demo.entity.Lawyer;
import java.util.Collection;
import java.util.Collections;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class LawyerPrincipal implements UserDetails {

  private final Lawyer lawyer;

  // 생성자: Lawyer 엔티티만 받습니다.
  public LawyerPrincipal(Lawyer lawyer) {
    this.lawyer = lawyer;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptyList();
  }

  @Override
  public String getPassword() {
    return null;
  }

  @Override
  public String getUsername() {
    return lawyer.getId().toString();
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
  public String getName() {
    return lawyer.getName();
  }
}