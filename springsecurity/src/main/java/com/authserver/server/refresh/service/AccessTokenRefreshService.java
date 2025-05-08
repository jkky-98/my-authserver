package com.authserver.server.refresh.service;

import com.authserver.server.refresh.dto.AccessTokenRefreshResponse;
import com.authserver.server.refresh.exception.InvalidRefreshTokenException;

public interface AccessTokenRefreshService {
    /**
     * @param grantType      must be "refresh_token"
     * @param oldRefreshToken 클라이언트가 보낸 리프레시 토큰
     * @return 발급된 새 액세스·리프레시 토큰과 만료시간을 담은 DTO
     * @throws InvalidRefreshTokenException  검증 실패 시
     */
    AccessTokenRefreshResponse refresh(String grantType, String oldRefreshToken);
}
