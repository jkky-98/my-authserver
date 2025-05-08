package com.authserver.server.repository;

import com.authserver.server.domain.Member;
import com.authserver.server.refresh.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByMemberId(Long memberId);
    Optional<RefreshToken> findByToken(String refreshToken);
    void deleteByMember(Member member);
    List<RefreshToken> findAllByMemberAndRevokedFalse(Member member);
}
