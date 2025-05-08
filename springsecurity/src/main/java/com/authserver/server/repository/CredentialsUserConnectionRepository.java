package com.authserver.server.repository;

import com.authserver.server.domain.CredentialsUserConnection;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialsUserConnectionRepository extends JpaRepository<CredentialsUserConnection, Long> {
    Optional<CredentialsUserConnection> findByMemberEmail(String email);
    Optional<CredentialsUserConnection> findByMember_MemberUuid(String memberUUID);
}
