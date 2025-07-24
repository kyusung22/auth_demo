package com.example.demo.service;

import com.example.demo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.*;
import java.util.*;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

  private static final Logger log = LoggerFactory.getLogger(CustomOAuth2UserService.class);

  private final UserRepository repo;
  public CustomOAuth2UserService(UserRepository repo) {
    this.repo = repo;
  }

  @Override
  public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
    // 1) 실제 카카오가 내려준 속성 전체와 userNameAttributeName(id 키)를 로깅
    OAuth2User oauth = new DefaultOAuth2UserService().loadUser(req);
    String userNameAttr = req.getClientRegistration()
        .getProviderDetails()
        .getUserInfoEndpoint()
        .getUserNameAttributeName();
    log.debug("Kakao user attributes: {}", oauth.getAttributes());
    Object rawId = oauth.getAttribute(userNameAttr);
    log.debug("Resolved userNameAttributeName '{}' = {}", userNameAttr, rawId);

    // 1) Null-safe 체크: id가 없으면 예외
    if (rawId == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error("invalid_user_info", "Kakao ID is null", null),
          "Kakao에서 사용자 ID(id) 정보를 가져올 수 없습니다."
      );
    }

    // 2) Long 변환
    Long kakaoId = Long.valueOf(rawId.toString());
    String email = (String) ((Map<?,?>) oauth.getAttribute("kakao_account")).get("email");

    // 3) 기존 사용자 조회, 없으면 생성
    User user = repo.findById(kakaoId)
        .orElseGet(() -> repo.save(new User(kakaoId, email, List.of("ROLE_USER"))));

    // 4) 스프링 시큐리티용 OAuth2User 반환
    return new DefaultOAuth2User(
        List.of(() -> "ROLE_USER"),
        oauth.getAttributes(),
        userNameAttr  // "id"
    );
  }
}
