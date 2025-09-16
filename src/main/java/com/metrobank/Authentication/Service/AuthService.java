package com.metrobank.Authentication.Service;

import com.metrobank.Authentication.Dto.*;
import com.metrobank.Authentication.Entity.LoginAttempt;
import com.metrobank.Authentication.Entity.Role;
import com.metrobank.Authentication.Entity.User;
import com.metrobank.Authentication.Repository.LoginAttemptRepository;
import com.metrobank.Authentication.Repository.UserRepository;
import com.metrobank.Authentication.Util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final OtpService otpService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthService(UserRepository userRepository, LoginAttemptRepository loginAttemptRepository, OtpService otpService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.loginAttemptRepository = loginAttemptRepository;
        this.otpService = otpService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    boolean requiresPasswordChange;

    @Transactional
    public AuthResponse authenticate(LoginRequest request, String ipAddress, String userAgent) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            logLoginAttempt(userOpt.get(), ipAddress, userAgent, false,"User not found");
            return new AuthResponse("Invalid credentials", false, false);
        }

        User user = userOpt.get();

        if (user.isAccountLocked()) {
            logLoginAttempt(user, ipAddress, userAgent, false, "Account locked");
            return new AuthResponse("Account is locked. Please contact administrator.", false, false);
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            handleFailedLogin(user, ipAddress, userAgent);
            return new AuthResponse("Invalid credentials", false, false);
        }

        // Reset failed login attempts
        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        // Send OTP
        otpService.sendOtp(user);

        requiresPasswordChange = passwordEncoder.matches("DefaultPassword123", request.getPassword());

        logLoginAttempt(user, ipAddress, userAgent, true, null);
        return new AuthResponse("OTP sent to your " + user.getOtpPreference().toString().toLowerCase(),
                true, requiresPasswordChange);
    }

    @Transactional
    public AuthResponse verifyOtp(OtpRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        if (!otpService.verifyOtp(user, request.getOtpCode())) {
            return new AuthResponse("Invalid or expired OTP", false, false);
        }

        if (requiresPasswordChange) {
            return new AuthResponse("Please change your default password", false, true);
        }

        return createAuthResponse(user, "Login successful");
    }

    @Transactional
    public AuthResponse changePassword(PasswordChangeRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        return createAuthResponse(user, "Password changed successfully");
    }

    private void handleFailedLogin(User user, String ipAddress, String userAgent) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        int MAX_FAILED_ATTEMPTS = 3;
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            logLoginAttempt(user, ipAddress, userAgent, false, "Account locked after max attempts");
        } else {
            logLoginAttempt(user, ipAddress, userAgent, false, "Invalid password");
        }

        userRepository.save(user);
    }

    private void logLoginAttempt(User user, String ipAddress, String userAgent, boolean success, String reason) {
        LoginAttempt attempt = LoginAttempt.builder()
                .user(user)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .successful(success)
                .failureReason(reason)
                .build();

        loginAttemptRepository.save(attempt);
    }

    private AuthResponse createAuthResponse(User user, String message) {
        String token = jwtUtil.generateToken(user.getId(), user.getRole().toString());
        String redirectUrl = getRedirectUrl(user.getRole());

        AuthResponse response = new AuthResponse(message, false, false);
        response.setToken(token);
        response.setRole(user.getRole().toString());
        response.setRedirectUrl(redirectUrl);
        return response;
    }

    private String getRedirectUrl(Role role) {
        return switch (role) {
            case ADMIN -> "/admin/dashboard";
            case EMPLOYEE -> "/employee/dashboard";
        };
    }
}
