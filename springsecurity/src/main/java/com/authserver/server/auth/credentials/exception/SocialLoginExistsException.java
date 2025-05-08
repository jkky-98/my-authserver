package com.authserver.server.auth.credentials.exception;

public class SocialLoginExistsException extends RuntimeException {
    public SocialLoginExistsException(String message) {
        super(message);
    }
}
