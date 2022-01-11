package com.example.security1.auth;

import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// 시큐리티 설정에서 loginProcessingUrl을 /login으로 설정했기때문에
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어있는 loadUserByUsername 메소드가 실행됨
// 이때 loginForm.html 의 username 필드의 이름이 username으로 되어있어야 loadUserByName의 파라미터로 매핑이 되기때문에 이름 주의
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    // Security Session( Authentication( UserDetails ) ) )
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user != null) return new PrincipalDetails(user);
        else return null;
    }
}
