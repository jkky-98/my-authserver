package com.authserver.server.auth.credentials.dto;


public record CredentialsLoginResponse(
        String accessToken,
        String refreshToken
) {
}
