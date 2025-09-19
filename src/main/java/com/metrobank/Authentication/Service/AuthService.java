package com.metrobank.Authentication.Service;

import com.google.zxing.WriterException;
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

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final TotpService totpService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int MAX_TOTP_ATTEMPTS = 3;

    @Autowired
    public AuthService(UserRepository userRepository, LoginAttemptRepository loginAttemptRepository,
                       TotpService totpService, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.loginAttemptRepository = loginAttemptRepository;
        this.totpService = totpService;
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

        // Check if user needs TOTP setup
        if (totpService.requiresTotpSetup(user)) {
            try {
                return setupTotpForUser(user);
            } catch (Exception e) {
                return new AuthResponse("Error setting up TOTP. Please try again.", false, false);
            }
        }

        // Check TOTP cooldown
        if (user.isTotpCooldownActive()) {
            return new AuthResponse("TOTP attempts exceeded. Please try again later.",
                    user.getTotpCooldownEndTime(), 0);
        }

        // Request TOTP verification
        return new AuthResponse("Please enter your Google Authenticator code", true, false);
    }

    @Transactional
    public AuthResponse setupTotpForUser(User user) throws WriterException, IOException {
        String secret = totpService.generateTotpSecret(user);
        String qrCodeUrl = totpService.generateQrCodeUrl(user);
        String qrCodeImage = totpService.generateQrCodeImage(user);

        TotpSetupResponse totpSetup = new TotpSetupResponse(
                secret,
                qrCodeUrl,
                qrCodeImage,
                "MetroBank eITR",
                user.getUsername() + " (" + user.getName() + ")"
        );

        return new AuthResponse("TOTP setup required. Please scan the QR code with Google Authenticator.", totpSetup);
    }

    @Transactional
    public AuthResponse verifyTotp(TotpRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        // Check TOTP cooldown
        if (user.isTotpCooldownActive()) {
            return new AuthResponse("TOTP verification is temporarily disabled. Please try again later.",
                    user.getTotpCooldownEndTime(), 0);
        }

        boolean totpValid = totpService.verifyTotpCode(user, request.getTotpCode());

        if (!totpValid) {
            user.setFailedTotpAttempts(user.getFailedTotpAttempts() + 1);

            if (user.getFailedTotpAttempts() >= MAX_TOTP_ATTEMPTS) {
                user.setTotpCooldown();
                userRepository.save(user);
                return new AuthResponse("Maximum TOTP attempts reached. Please try again in 30 minutes.",
                        user.getTotpCooldownEndTime(), 0);
            }

            userRepository.save(user);
            int remainingAttempts = MAX_TOTP_ATTEMPTS - user.getFailedTotpAttempts();
            return new AuthResponse("Invalid TOTP code. " + remainingAttempts + " attempts remaining.",
                    null, remainingAttempts);
        }

        // Clear TOTP attempts on successful verification
        user.clearTotpCooldown();
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
    public AuthResponse getTotpSetup(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        if (!totpService.requiresTotpSetup(user)) {
            return new AuthResponse("TOTP is already set up for this user", false, false);
        }

        try {
            return setupTotpForUser(user);
        } catch (Exception e) {
            return new AuthResponse("Error generating TOTP setup. Please try again.", false, false);
        }
    }

    @Transactional
    public AuthResponse resetTotpSecret(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return new AuthResponse("User not found", false, false);
        }

        User user = userOpt.get();

        try {
            String newSecret = totpService.resetTotpSecret(user);
            String qrCodeUrl = totpService.generateQrCodeUrl(user);
            String qrCodeImage = totpService.generateQrCodeImage(user);

            TotpSetupResponse totpSetup = new TotpSetupResponse(
                    newSecret,
                    qrCodeUrl,
                    qrCodeImage,
                    "MetroBank eITR",
                    user.getUsername() + " (" + user.getName() + ")"
            );

            return new AuthResponse("TOTP secret has been reset. Please scan the new QR code.", totpSetup);
        } catch (Exception e) {
            return new AuthResponse("Error resetting TOTP secret. Please try again.", false, false);
        }
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
        response.setUser_id(user.getUser_id());
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
