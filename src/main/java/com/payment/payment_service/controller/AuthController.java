package com.payment.payment_service.controller;

import com.payment.payment_service.dto.ApiResponse;
import com.payment.payment_service.dto.LoginRequestDTO;
import com.payment.payment_service.dto.LoginResponseDTO;
import com.payment.payment_service.dto.RegisterRequestDTO;
import com.payment.payment_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/register
     *
     * Request body:
     * {
     *   "username": "john",
     *   "email": "john@example.com",
     *   "password": "secret123",
     *   "role": "CUSTOMER"          // optional, defaults to CUSTOMER
     * }
     *
     * Returns a JWT token immediately — user is logged in on registration.
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> register(
            @Valid @RequestBody RegisterRequestDTO request) {

        LoginResponseDTO response = authService.register(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success(response, "Registration successful"));
    }

    /**
     * POST /api/auth/login
     *
     * Request body:
     * {
     *   "username": "john",
     *   "password": "secret123"
     * }
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> login(
            @Valid @RequestBody LoginRequestDTO request) {

        LoginResponseDTO response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(response, "Login successful"));
    }
}
