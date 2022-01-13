package com.example.security1.auth.oauth;

import com.example.security1.auth.PrincipalDetails;
import com.example.security1.auth.oauth.provider.FacebookUserInfo;
import com.example.security1.auth.oauth.provider.GoogleUserInfo;
import com.example.security1.auth.oauth.provider.NaverUserInfo;
import com.example.security1.auth.oauth.provider.OAuth2UserInfo;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getAccessToken : " + userRequest.getAccessToken().getTokenValue());
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User.getAttributes() : " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("google login call");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("facebook login call");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("naver login call");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>)oAuth2User.getAttributes().get("response"));
        }
        else{
            System.out.println("can't login using another sns");
        }

        String provider = oAuth2UserInfo.getProvider();
        // google -> sub, facebook -> id
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User findUser = userRepository.findByUsername(username);
        if(findUser == null){
            findUser = User.builder().username(username).email(email)
                    .role(role).provider(provider).providerId(providerId)
                    .build();
            userRepository.save(findUser);
        }
        else{
            System.out.println("로그인을 이미 한 적이 있습니다.");
        }

        return new PrincipalDetails(findUser, oAuth2User.getAttributes());
    }
}
