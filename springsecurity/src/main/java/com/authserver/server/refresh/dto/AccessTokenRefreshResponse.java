package com.authserver.server.refresh.dto;

public record AccessTokenRefreshResponse(
        String accessToken,
        String refreshToken,
        long    expiresIn   // 초 단위
) { }
