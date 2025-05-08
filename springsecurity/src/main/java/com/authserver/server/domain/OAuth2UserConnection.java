package com.authserver.server.domain;

import com.authserver.server.auth.oauth2.user.OAuth2Provider;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * 소셜 로그인 연동 정보 엔티티
 */
@Entity
@Table(name = "oauth2_user_connections",
        uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "providerId"}))
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class OAuth2UserConnection {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OAuth2Provider provider;

    @Column(nullable = false)
    private String providerId;

    @Column(nullable = false)
    private Instant linkedAt;
}