package com.payment.payment_service.dto;


import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class LoginResponseDTO {

    private String token;
    private String username;
    private List<String> roles;
    private long expiresIn; // ms
}
