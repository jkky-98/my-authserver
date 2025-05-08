package com.authserver.server.auth.credentials.exception;

import com.authserver.server.exception.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CredentialsExceptionHandler {

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateEmail(DuplicateEmailException ex) {
        var body = ErrorResponse.of(HttpStatus.CONFLICT.value(), ex.getMessage());
        // 409 Conflict: 이미 존재하는 리소스
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(body);
    }

    @ExceptionHandler(SocialLoginExistsException.class)
    public ResponseEntity<ErrorResponse> handleSocialLoginExists(SocialLoginExistsException ex) {
        var body = ErrorResponse.of(HttpStatus.CONFLICT.value(), ex.getMessage());
        // 409 Conflict: 소셜 로그인 이력이 있는 이메일
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleBadRequest(IllegalArgumentException ex) {
        var body = ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), ex.getMessage());
        // 400 Bad Request: 유효하지 않은 요청
        return ResponseEntity
                .badRequest()
                .body(body);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                ex.getMessage()
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }


}
