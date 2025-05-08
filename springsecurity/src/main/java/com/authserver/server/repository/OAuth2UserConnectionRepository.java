package com.authserver.server.repository;

import com.authserver.server.domain.Member;
import com.authserver.server.domain.OAuth2UserConnection;
import com.authserver.server.auth.oauth2.user.OAuth2Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2UserConnectionRepository extends JpaRepository<OAuth2UserConnection, Long> {
    Optional<OAuth2UserConnection> findByProviderAndProviderId(OAuth2Provider provider, String providerId);
    void deleteByMemberAndProvider(Member member, OAuth2Provider provider);
}
