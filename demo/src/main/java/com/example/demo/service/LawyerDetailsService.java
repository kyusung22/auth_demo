package com.example.demo.service;

import com.example.demo.entity.Lawyer;
import com.example.demo.repository.LawyerRepository;
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
    Lawyer lawyer = repo.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("변호사 계정이 없습니다이"));

    return new org.springframework.security.core.userdetails.User(
        lawyer.getUsername(),
        lawyer.getPassword(),
        AuthorityUtils.createAuthorityList(lawyer.getRoles().toArray(new String[0]))
    );
  }


}
