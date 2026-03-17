package com.payment.payment_service.service;

import com.payment.payment_service.dto.LoginRequestDTO;
import com.payment.payment_service.dto.LoginResponseDTO;
import com.payment.payment_service.dto.RegisterRequestDTO;
import com.payment.payment_service.enums.Role;
import com.payment.payment_service.model.User;
import com.payment.payment_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Transactional
    public LoginResponseDTO register(RegisterRequestDTO request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already taken: " + request.getUsername());
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already registered: " + request.getEmail());
        }

        Role role = request.getRole() != null ? request.getRole() : Role.CUSTOMER;

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(role))
                .enabled(true)
                .build();

        userRepository.save(user);
        log.info("New user registered: username={} role={}", user.getUsername(), role);

        // Issue a token immediately so the user is logged in after registration
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String token = null;
        try {
            token = jwtService.generateToken(userDetails);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return buildLoginResponse(token, userDetails);
    }
    public LoginResponseDTO login(LoginRequestDTO request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        String token = jwtService.generateToken(userDetails);

        log.info("User logged in: {}", request.getUsername());

        return buildLoginResponse(token, userDetails);
    }

    private LoginResponseDTO buildLoginResponse(String token, UserDetails userDetails) {
        return LoginResponseDTO.builder()
                .token(token)
                .username(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream()
                        .map(a -> a.getAuthority().replace("ROLE_", ""))
                        .collect(Collectors.toList()))
                .expiresIn(jwtExpiration)
                .build();
    }
}
