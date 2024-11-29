package com.ict.edu3.domain.auth.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ict.edu3.common.util.JwtUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api/auth")
public class AuthAPIController {
  @Autowired
  private JwtUtil jwtUtil;

  @PostMapping("/generate-token")
  public String postMethodName(@RequestBody Map<String, String> request) {
      
      // 클라이언트가 userName이라는 key에 정보를 보냈다고 가정하자
      String userName = request.get("userName");

      // jwt를 생성할 때 더많은 정보를 추가 할 수있다.
      Map<String, Object> claims = new HashMap<>();
      claims.put("role", "USER");
      
      return jwtUtil.generateToken(userName, claims);
  }
  
}
