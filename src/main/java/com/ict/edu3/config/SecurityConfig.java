package com.ict.edu3.config;


import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.ict.edu3.common.util.JwtUtil;
import com.ict.edu3.domain.auth.service.MyUserDetailService;
import com.ict.edu3.jwt.JwtRequestFilter;

import lombok.extern.slf4j.Slf4j;

@Slf4j // Lombok의 어노테이션으로, 로그 객체(log)를 자동으로 생성합니다. 예) log.info("메시지");를 사용하여 디버깅 메시지를 출력.
@Configuration // Spring Bean 설정 클래스를 나타냅니다. Spring 컨텍스트에 필요한 Bean을 정의합니다.
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter; // JWT 요청을 처리하는 필터 클래스. 모든 요청에서 JWT를 검사하고 인증을 처리하기 위해 사용됩니다
    private final JwtUtil jwtUtil;
    private final MyUserDetailService userDetailService;

    // 의존성 주입
    // 생성자 주입을 통해 Spring 컨텍스트에서 JwtRequestFilter Bean을 받아옵니다.
    public SecurityConfig(JwtRequestFilter jwtRequestFilter, JwtUtil jwtUtil, MyUserDetailService userDetailService) {
        log.info("SecurityConfig 호출\n");
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUtil = jwtUtil;
        this.userDetailService = userDetailService;
    }

    // 서버에 들어는 모든 요청은 SecurityFilterChain 을 거친다.
    // addFilterBefore 때문에 JwtRequestFilter가 먼저 실행된다.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("SecurityFilterChain 호출\n");
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                // 요청별 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/upload/**").permitAll()  // URL경로
                        .requestMatchers("/oauth2/**").permitAll()  // URL경로
                        // 특정 URL에 인증없이 허용
                        .requestMatchers("/api/members/join", "/api/members/login",
                         "/api/members/logout", "/api/guestbook/list", "/api/guestbook/detail/**", 
                         "api/guestbook/download/**").permitAll()
                        // 나머지는 인증 필요
                        .anyRequest().authenticated())
                 // oauth2Login 설정
                 // successHandler => 로그인 성공시 호출
                 // userInfoEndpoint => 인증과정에서 인증된 사용자의 정보를 제공하는 API 엔드포인트
                 //                     (사용자 정보를 가져오는 역할을 한다.)       
                .oauth2Login(oauth2 -> oauth2
                .successHandler(oAuth2AuthenticationSuccessHandler())
                .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService())))
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler(){
        return new OAuth2AuthenticationSuccessHandler(jwtUtil, userDetailService, "http://localhost:3000");
    } 

    @Bean
    public OAuth2UserService<OAuth2UserReauest, OAuth2User> oAuth2UserService() {
        return new CustomerOAuth2UserService();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // 허용할 Origin 설정
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        // 허용할 http 메서드 설정
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // 허용할 헤더 설정
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        // 인증정보 허용
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}