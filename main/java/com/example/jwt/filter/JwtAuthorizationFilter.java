package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.JwtProperties;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.respository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


// 스프링 시큐리티의 filter 중 BasicAuthenticationFilter는
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 실행됨
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 들어옴");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);

        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            System.out.println("error here");
            chain.doFilter(request, response);
            return;
        }

        String token = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
                .getClaim("username").asString();

        if (username != null) {
            System.out.println("username : " + username);
            User findUser = userRepository.findByUsername(username);
            System.out.println("findUser : " + findUser);
            System.out.println("findUser.getRoles() : " + findUser.getRoles());
            System.out.println("findUser.getRoleList() : "  + findUser.getRoleList().get(0));
            PrincipalDetails principalDetails = new PrincipalDetails(findUser);
            System.out.println("getAuthorities = " + principalDetails.getAuthorities());
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }

    }
}
