package com.example.demo.service;

import com.example.demo.entity.Lawyer;
import com.example.demo.entity.Lawyer.CertificationStatus;
import com.example.demo.repository.LawyerRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class LawyerDetailsService implements UserDetailsService {

  private final LawyerRepository repo;
  public LawyerDetailsService(LawyerRepository repo) {
    this.repo = repo;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Lawyer lawyer = repo.findByLoginEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("변호사 계정이 없습니다이"));

    if(lawyer.getCertificationStatus() != CertificationStatus.APPROVED) {
      throw new BadCredentialsException("인증되지 않은 계정입니다. 관리자에게 문의하세요.");
    }

    return new org.springframework.security.core.userdetails.User(
        lawyer.getLoginEmail(),
        lawyer.getPasswordHash(),
        AuthorityUtils.createAuthorityList("ROLE_LAYWER")
    );
  }


}
