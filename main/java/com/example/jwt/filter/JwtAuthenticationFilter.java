package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.JwtProperties;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;

// 스프링 시큐리티에서 *UsernamePasswordAuthenticationFilter*는
// /login 으로 요청해서 username, password를 전송하면 (post) 동작함


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // 1. username, password를 받아서
    // 2. 정상인지 로그인 시도 -> *authenticationManager*로 로그인 시도를 하면
    // PrincipalDetailsService가 호출되어 loadUserByUsername() 메소드가 실행됨
    // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
    // 4. JWT 토큰을 만들어서 응답

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

        try {
//            BufferedReader reader = request.getReader();
//            String input = null;
//            while((input = reader.readLine()) != null) System.out.println(input);

            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이때 PrincipalDetailsService의 loadUserByUsername()가 실행됨
            Authentication authentication = authenticationManager.authenticate(token);

            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principal.getUser().getUsername());

            //여기까지 왔으면 authentication 객체가 session 영역에 저장된 것 -> 로그인이 되었다는 뜻
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("run successfulAuthentication()");
        PrincipalDetails principal = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principal.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principal.getUser().getId())
                .withClaim("username", principal.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        System.out.println(jwtToken);
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
