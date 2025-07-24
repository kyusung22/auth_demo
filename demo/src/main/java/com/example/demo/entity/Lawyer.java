package com.example.demo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.util.List;
import lombok.Data;

@Entity
@Data
public class Lawyer {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "login_email", nullable = false, unique = true, length = 50)
  private String loginEmail;

  @Column(name = "password_hash", nullable = false, length = 255)
  private String passwordHash;


  @Column(nullable = false, length = 10)
  private String name;

  @Column(columnDefinition = "TEXT")
  private String introduction;

  @Enumerated(EnumType.STRING)
  @Column(name = "certification_status", nullable = false)
  private CertificationStatus certificationStatus = CertificationStatus.PENDING;

  @Column(name = "consultation_count", nullable = false)
  private int consultationCount = 0;

  public enum CertificationStatus {
    PENDING, APPROVED, REJECTED
  }

}