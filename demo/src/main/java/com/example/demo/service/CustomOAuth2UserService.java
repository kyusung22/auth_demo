package com.example.demo.service;

import com.example.demo.repository.UserRepository;
import org.springframework.stereotype.Service;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.*;
import java.util.*;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User>{

  private final UserRepository repo;
  public CustomOAuth2UserService(UserRepository repo) {
    this.repo = repo;
  }

  @Override
  public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException{
    OAuth2User oauth = new DefaultOAuth2UserService().loadUser(req);
    Long kakaoId = oauth.getAttribute("Id");
    String email = (String) ((Map) oauth.getAttribute("kakao_account")).get("email");

    User user = repo.findById(kakaoId)
        .orElseGet(() -> repo.save(new User(kakaoId, email, List.of("ROLE_USER"))));

    return new DefaultOAuth2User(
      List.of(() -> "ROLE_USER"), oauth.getAttributes(), "id"
    );
  }

}
