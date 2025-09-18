package com.metrobank.Authentication.Service;

import com.metrobank.Authentication.Dto.*;
import com.metrobank.Authentication.Entity.LoginAttempt;
import com.metrobank.Authentication.Entity.Role;
import com.metrobank.Authentication.Entity.User;
import com.metrobank.Authentication.Repository.LoginAttemptRepository;
import com.metrobank.Authentication.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final OtpService otpService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int MAX_OTP_ATTEMPTS = 3;

    @Autowired
    public AuthService(UserRepository userRepository, LoginAttemptRepository loginAttemptRepository,
                       OtpService otpService, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.loginAttemptRepository = loginAttemptRepository;
        this.otpService = otpService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse authenticate(LoginRequest request, String ipAddress, String userAgent) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("Invalid credentials", false, false);
        }

        User user = userOpt.get();

        // Check if account is locked or in cooldown
        if (user.isAccountLocked() || user.isLoginCooldownActive()) {
            logLoginAttempt(user, ipAddress, userAgent, false, "Account locked or in cooldown");

            if (user.isLoginCooldownActive()) {
                return new AuthResponse("Account is locked due to multiple failed attempts. Try again later.",
                        user.getLockoutEndTime(), 0);
            } else {
                return new AuthResponse("Account is locked. Please contact administrator.", null, 0);
            }
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return handleFailedLogin(user, ipAddress, userAgent);
        }

        // Reset failed login attempts on successful password verification
        user.setFailedLoginAttempts(0);
        user.unlockAccount();
        userRepository.save(user);

        logLoginAttempt(user, ipAddress, userAgent, true, null);

        // Check if user has OTP preference set
        if (user.getOtpPreference() == null) {
            return new AuthResponse("Please select your preferred OTP method", true);
        }

        // Check OTP cooldown
        if (user.isOtpCooldownActive()) {
            return new AuthResponse("OTP attempts exceeded. Please try again later.",
                    user.getOtpCooldownEndTime(), 0);
        }

        // Send OTP
        otpService.sendOtp(user);
        return new AuthResponse("OTP sent to your " + user.getOtpPreference().toString().toLowerCase(),
                true, false);
    }

    @Transactional
    public AuthResponse selectOtpPreferenceAndSendOtp(SelectOtpPreference request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        // Check OTP cooldown
        if (user.isOtpCooldownActive()) {
            return new AuthResponse("OTP attempts exceeded. Please try again later.",
                    user.getOtpCooldownEndTime(), 0);
        }

        // Update OTP preference
        user.setOtpPreference(request.getOtpPreference());
        userRepository.save(user);

        // Send OTP
        otpService.sendOtp(user);
        return new AuthResponse("OTP sent to your " + user.getOtpPreference().toString().toLowerCase(),
                true, false);
    }

    @Transactional
    public AuthResponse verifyOtp(OtpRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        // Check OTP cooldown
        if (user.isOtpCooldownActive()) {
            return new AuthResponse("OTP verification is temporarily disabled. Please try again later.",
                    user.getOtpCooldownEndTime(), 0);
        }

        boolean otpValid = otpService.verifyOtp(user, request.getOtpCode());

        if (!otpValid) {
            user.setFailedOtpAttempts(user.getFailedOtpAttempts() + 1);

            if (user.getFailedOtpAttempts() >= MAX_OTP_ATTEMPTS) {
                user.setOtpCooldown();
                userRepository.save(user);
                return new AuthResponse("Maximum OTP attempts reached. Please try again in 30 minutes.",
                        user.getOtpCooldownEndTime(), 0);
            }

            userRepository.save(user);
            int remainingAttempts = MAX_OTP_ATTEMPTS - user.getFailedOtpAttempts();
            return new AuthResponse("Invalid or expired OTP. " + remainingAttempts + " attempts remaining.",
                    null, remainingAttempts);
        }

        // Clear OTP attempts on successful verification
        user.clearOtpCooldown();
        userRepository.save(user);

        // Check if password change is required (using BCrypt encoded check)
        if (isDefaultPassword(user, "DefaultPassword123!")) {
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

    @Transactional
    public AuthResponse resendOtp(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        // Check OTP cooldown
        if (user.isOtpCooldownActive()) {
            return new AuthResponse("OTP resend is temporarily disabled. Please try again later.",
                    user.getOtpCooldownEndTime(), 0);
        }

        if (user.getOtpPreference() == null) {
            return new AuthResponse("Please select your preferred OTP method first", true);
        }

        otpService.sendOtp(user);
        return new AuthResponse("OTP resent to your " + user.getOtpPreference().toString().toLowerCase(),
                true, false);
    }

    private AuthResponse handleFailedLogin(User user, String ipAddress, String userAgent) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

        if (user.getFailedLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
            user.lockAccount();
            logLoginAttempt(user, ipAddress, userAgent, false, "Account locked after max attempts");
            userRepository.save(user);
            return new AuthResponse("Account locked due to multiple failed attempts. Try again after 24 hours.",
                    user.getLockoutEndTime(), 0);
        } else {
            logLoginAttempt(user, ipAddress, userAgent, false, "Invalid password");
            userRepository.save(user);
            int remainingAttempts = MAX_LOGIN_ATTEMPTS - user.getFailedLoginAttempts();
            return new AuthResponse("Invalid credentials. " + remainingAttempts + " attempts remaining.",
                    null, remainingAttempts);
        }
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
        String token = jwtService.generateToken(user);
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

    private boolean isDefaultPassword(User user, String defaultPassword) {
        return passwordEncoder.matches(defaultPassword, user.getPassword());
    }
}
