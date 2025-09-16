package com.metrobank.Authentication.Dto;

import lombok.*;
import lombok.experimental.Tolerate;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String message;
    private boolean requiresOtp;
    private boolean requiresPasswordChange;
    private String role;
    private String redirectUrl;

    // Custom constructor for common use case
    @Tolerate
    public AuthResponse(String message, boolean requiresOtp, boolean requiresPasswordChange) {
        this.message = message;
        this.requiresOtp = requiresOtp;
        this.requiresPasswordChange = requiresPasswordChange;
    }
}
