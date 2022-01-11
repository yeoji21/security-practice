package com.example.security1.auth.oauth;

import com.example.security1.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
//    private final BCryptPasswordEncoder encoder;
    private final UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User.getAttributes() : " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
//        String password = encoder.encode("get in there");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";


        User findUser = userRepository.findByUsername(username);
        if(findUser == null){
            findUser = User.builder().username(username).email(email)
                    .role(role).provider(provider).providerId(providerId)
                    .build();
            userRepository.save(findUser);
        }

        return new PrincipalDetails(findUser, oAuth2User.getAttributes());
    }
}
