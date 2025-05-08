package com.authserver.server.auth.credentials.service;

import com.authserver.server.domain.CredentialsUserConnection;
import com.authserver.server.domain.Member;
import com.authserver.server.repository.CredentialsUserConnectionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CredentialsUserDetailsService implements UserDetailsService {

    private final CredentialsUserConnectionRepository credentialsUserConnectionRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // 1) 이메일로 자격증명 연결 정보 조회
        CredentialsUserConnection credentialsUserConnection = credentialsUserConnectionRepository.findByMemberEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 사용자입니다: " + email));

        Member member = credentialsUserConnection.getMember();

        String[] authorities = member.getRoles().stream()
                .map(Enum::name)
                .toArray(String[]::new);

        return User.builder()
                .username(member.getMemberUuid())
                .password(credentialsUserConnection.getPasswordHash())
                .authorities(authorities)
                .build();
    }
}
