package com.ict.edu3.common.util;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

// @Component: Spring에서 이 클래스를 Bean으로 등록하여, 다른 클래스에서 의존성 주입으로 사용할 수 있다.
@Component
public class JwtUtil { // 주요 기능 : JWT 생성 (generateToken)  |  JWT 검증 (validateToken)  |  JWT 정보 추출 (extractClaim 등)

    @Value("${jwt.secret}") // @Value 어노테이션을 통해 application.properties나 application.yml에서 값을 주입받습니다.
    private String secret; // JWT를 서명할 때 사용하는 비밀키

    @Value("${jwt.expiration}")
    private long expiration; // JWT의 유효기간 (밀리초 단위).

    // SecretKey 생성
    private SecretKey getKey() { // JWT 서명에 사용할 SecretKey를 생성합니다.
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8); // 비밀키를 UTF-8 바이트 배열로 변환한 뒤
        return Keys.hmacShaKeyFor(keyBytes); // HMAC SHA-256 알고리즘을 지원하는 키 객체를 반환합니다.
    }

    // 토큰 생성
    public String generateToken(String id) { // 기본적인 토큰 생성 메서드.
        Map<String, Object> claims = new HashMap<>(); // claims라는 Map에 데이터를 추가하여 
        claims.put("phone", "010-7777-9999"); 
        return generateToken(id, claims); // JWT의 payload 부분에 포함시킨다.
    }

    // 토큰 생성
    // - JWT의 세 가지 구성요소 생성:
    //    1. Header: 서명 알고리즘 (HMAC-SHA256).
    //    2. Payload: 클레임 데이터 (claims 및 username 등).
    //    3. Signature: Header와 Payload를 secret으로 서명한 값.
    //    4. compact() 메서드로 최종 JWT 문자열 생성.
    public String generateToken(String username, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)    // Payload에 포함될 클레임 데이터
                .setSubject(username) // 주체 (보통 사용자 ID)
                .setIssuedAt(new Date())  // 발급 시간
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 만료 시간
                .signWith(getKey(), SignatureAlgorithm.HS256) // 서명: HMAC-SHA256
                .compact();  // 최종 JWT 문자열 반환
    }

    // 토큰의 데이터 추출
    // 모든 클레임 정보 추출
    //  - JWT를 파싱하여 Payload 부분(Claims)을 반환합니다.
    //  - 서명을 검증하여 위변조 여부를 확인합니다.
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder() 
                .setSigningKey(getKey())  // 서명 검증에 사용할 키
                .build()
                .parseClaimsJws(token)  // JWT 파싱 및 검증
                .getBody(); // Payload 반환
    }

    // 특정 클레임 추출
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { // 특정 클레임을 추출할 수 있는 유틸리티 메서드.
        final Claims claims = extractAllClaims(token);  // 모든 클레임 추출
        return claimsResolver.apply(claims);  // 원하는 클레임 추출 (예 : 토큰의 만료 시간, 주체 정보 등을 추출.)
    }

    // 토근을 받아서 이름 추출한다.
    public String extractuserName(String token) {
      // JWT의 sub 필드에서 사용자 이름 또는 ID를 추출.
        return extractClaim(token, Claims::getSubject); // `sub` (주체) 클레임
    }

    // 토큰 검사
    // UserDetails는 유저 정보를 로드하며, 관리하는 역할 한다.
    public Boolean validateToken(String token, UserDetails userDetails) { //  토큰과 UserDetails의 사용자 정보(username)가 일치하는지 확인. | 토큰이 만료되지 않았는지도 함께 확인.
        // jwt 토큰에서 subject 정보를 가져오는 것
        final String username = extractuserName(token);  // 토큰에서 사용자 이름 추출
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));  // 일치 여부와 만료 여부 확인
    }

    // 만료 여부 점검
    public Boolean isTokenExpired(String token) { // 토큰의 만료 시간이 현재 시간보다 이전인지 확인.
        return extractExpiration(token).before(new Date()); // 현재 시간과 비교
    }

    //  만료 시간 추출
    public Date extractExpiration(String token) { //  JWT에서 만료 시간(exp) 클레임을 추출.
        return extractClaim(token, Claims::getExpiration);  // `exp` 클레임
    }
}