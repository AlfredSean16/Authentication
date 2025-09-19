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
    private boolean requiresTotp;
    private boolean requiresPasswordChange;
    private boolean requiresTotpSetup;
    private Long user_id;
    private String role;
    private String redirectUrl;
    private LocalDateTime cooldownEndTime;
    private int remainingAttempts;

    // For TOTP setup
    private TotpSetupResponse totpSetup;

    // Custom constructor for common use case
    @Tolerate
    public AuthResponse(String message, boolean requiresTotp, boolean requiresPasswordChange) {
        this.message = message;
        this.requiresTotp = requiresTotp;
        this.requiresPasswordChange = requiresPasswordChange;
    }

    @Tolerate
    public AuthResponse(String message, boolean requiresTotpSetup) {
        this.message = message;
        this.requiresTotpSetup = requiresTotpSetup;
    }

    // Constructor with cooldown info
    @Tolerate
    public AuthResponse(String message, LocalDateTime cooldownEndTime, int remainingAttempts) {
        this.message = message;
        this.cooldownEndTime = cooldownEndTime;
        this.remainingAttempts = remainingAttempts;
    }

    // Constructor for TOTP setup
    @Tolerate
    public AuthResponse(String message, TotpSetupResponse totpSetup) {
        this.message = message;
        this.requiresTotpSetup = true;
        this.totpSetup = totpSetup;
    }
}
