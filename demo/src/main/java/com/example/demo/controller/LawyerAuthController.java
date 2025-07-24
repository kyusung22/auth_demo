package com.example.demo.controller;

import com.example.demo.dto.LawyerLoginDto;
import com.example.demo.dto.LawyerSignupDto;
import com.example.demo.entity.Lawyer;
import com.example.demo.entity.Lawyer.CertificationStatus;
import com.example.demo.repository.LawyerRepository;
import com.example.demo.util.JwtUtil;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class LawyerAuthController {
  private final LawyerRepository lawyerRepo;
  private final PasswordEncoder pwEncoder;
  private final JwtUtil jwtUtil;
  private final AuthenticationManager authManager;

  public LawyerAuthController(LawyerRepository lawyerRepo, PasswordEncoder pwEncoder,
      AuthenticationManager authManager , JwtUtil jwtUtil) {
    this.lawyerRepo = lawyerRepo;
    this.pwEncoder = pwEncoder;
    this.jwtUtil = jwtUtil;
    this.authManager = authManager;
  }

  @PostMapping("/signup")
  public ResponseEntity<?> signup(@RequestBody LawyerSignupDto dto) {
    if (lawyerRepo.existsByLoginEmail(dto.getLoginEmail())) {
      return ResponseEntity.badRequest().body("이미 등록된 이메일입니다.");
    }

    Lawyer l = new Lawyer();
    l.setLoginEmail(dto.getLoginEmail());
    l.setPasswordHash(pwEncoder.encode(dto.getPassword()));
    l.setName(dto.getName());
    l.setIntroduction(dto.getIntroduction());
    l.setCertificationStatus(CertificationStatus.PENDING);
    l.setConsultationCount(0);
    lawyerRepo.save(l);

    return ResponseEntity.ok("가입 신청이 완료되었습니다.");
  }

  @PostMapping("/login/json")
  public ResponseEntity<?> loginJson(@RequestBody LawyerLoginDto dto) {
    if (dto.getLoginEmail() == null || dto.getPassword() == null) {
      return ResponseEntity.badRequest().body(Map.of("error", "이메일 또는 비밀번호 누락"));
    }

    try {
      // 1. 인증 시도
      Authentication authentication = authManager.authenticate(
          new UsernamePasswordAuthenticationToken(dto.getLoginEmail(), dto.getPassword())
      );

      String raw = dto.getPassword();
      String encoded = lawyerRepo.findByLoginEmail(dto.getLoginEmail())
          .get().getPasswordHash();
      boolean matches = pwEncoder.matches(raw, encoded);
      System.out.println("Password matches? " + matches);

      // 2. 성공 시 JWT 발급
      String token = jwtUtil.generateToken(
          authentication.getName(),
          authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .toList(), "USER"
      );

      // 3. 응답 반환
      return ResponseEntity.ok(Map.of(
          "token", token,
          "username", authentication.getName()
      ));

    } catch (BadCredentialsException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "비밀번호가 올바르지 않다."));
    } catch (UsernameNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(Map.of("error", "그런 계정은 없다."));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("error", "아무튼 실패"));
    }
  }

}