package com.metrobank.Authentication.Dto;

import lombok.*;
import lombok.experimental.Tolerate;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String message;
    private boolean requiresOtp;
    private boolean requiresPasswordChange;
    private boolean requiresOtpPreference;
    private String role;
    private String redirectUrl;
    private LocalDateTime cooldownEndTime;
    private int remainingAttempts;

    // Custom constructor for common use case
    @Tolerate
    public AuthResponse(String message, boolean requiresOtp, boolean requiresPasswordChange) {
        this.message = message;
        this.requiresOtp = requiresOtp;
        this.requiresPasswordChange = requiresPasswordChange;
    }

    @Tolerate
    public AuthResponse(String message, boolean requiresOtpPreference) {
        this.message = message;
        this.requiresOtpPreference = requiresOtpPreference;
    }

    // Constructor with cooldown info
    @Tolerate
    public AuthResponse(String message, LocalDateTime cooldownEndTime, int remainingAttempts) {
        this.message = message;
        this.cooldownEndTime = cooldownEndTime;
        this.remainingAttempts = remainingAttempts;
    }
}
