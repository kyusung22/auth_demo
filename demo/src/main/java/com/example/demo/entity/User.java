package com.example.demo.entity;

import jakarta.persistence.*;
import java.util.List;
import lombok.Data;

@Entity
@Data
public class User {
  @Id
  private Long id;
  private String email;

  @ElementCollection(fetch = FetchType.EAGER)
  private List<String> roles;

  // 1) JPA용 기본 생성자 (필수)
  public User() { }

  // 2) 편의용 All-args 생성자
  public User(Long id, String email, List<String> roles) {
    this.id = id;
    this.email = email;
    this.roles = roles;
  }
}
