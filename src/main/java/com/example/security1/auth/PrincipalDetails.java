package com.example.security1.auth;

import com.example.security1.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;


// 시큐리티의 로그인 진행이 완료되면 시큐리티 session을 만들어줌 (Security ContextHolder)
// 시큐리티 세션 내부에 들어갈 오브젝트 타입은 Authentication 타입의 객체
// 이 Authentication 객체 안에 User 정보가 있어야 함
// User 오브젝트 타입 또한 UserDetails 타입 객체로 제한됨

@Getter
@AllArgsConstructor
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails, OAuth2User {
    private final User user;
    private Map<String, Object> attributes;


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
