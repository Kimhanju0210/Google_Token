package org.example.ntoken.oauth.entity;

import org.example.ntoken.api.entity.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public interface UserPrincipall extends OAuth2User, UserDetails {
    static UserPrincipal create(User user) {
        return new UserPrincipal(
                user.getUserId(),
                user.getPassword(),
                user.getProviderType(),
                RoleType.USER,
                Collections.singletonList(new SimpleGrantedAuthority(RoleType.USER.getCode()))
        );
    }

    static UserPrincipal create(User user, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = create(user);
        userPrincipal.setAttributes(attributes);

        return userPrincipal;
    }

    @Override
    Map<String, Object> getAttributes();

    @Override
    Collection<? extends GrantedAuthority> getAuthorities();

    @Override
    String getName();

    @Override
    String getUsername();

    @Override
    boolean isAccountNonExpired();

    @Override
    boolean isAccountNonLocked();

    @Override
    boolean isCredentialsNonExpired();

    @Override
    boolean isEnabled();

    Map<String, Object> getClaims();

    OidcUserInfo getUserInfo();

    OidcIdToken getIdToken();

    String getUserId();

    String getPassword();

    ProviderType getProviderType();

    RoleType getRoleType();

    void setAttributes(Map<String, Object> attributes);
}
