package com.authserver.server.auth.credentials.dto;

import jakarta.validation.constraints.NotBlank;

public record CredentialsLoginRequest(
        @NotBlank(message = "이메일을 입력해주세요")
        String email,

        @NotBlank(message = "비밀번호를 입력해주세요")
        String password
) {}