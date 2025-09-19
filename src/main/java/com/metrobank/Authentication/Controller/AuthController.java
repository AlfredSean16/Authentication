package com.metrobank.Authentication.Controller;

import com.metrobank.Authentication.Dto.*;
import com.metrobank.Authentication.Service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        AuthResponse response = authService.authenticate(request, ipAddress, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-totp")
    public ResponseEntity<AuthResponse> verifyTotp(@Valid @RequestBody TotpRequest request) {
        AuthResponse response = authService.verifyTotp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<AuthResponse> changePassword(@Valid @RequestBody PasswordChangeRequest request) {
        AuthResponse response = authService.changePassword(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/totp-setup/{username}")
    public ResponseEntity<AuthResponse> getTotpSetup(@PathVariable String username) {
        AuthResponse response = authService.getTotpSetup(username);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-totp")
    public ResponseEntity<AuthResponse> resetTotpSecret(@RequestParam String username) {
        AuthResponse response = authService.resetTotpSecret(username);
        return ResponseEntity.ok(response);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
