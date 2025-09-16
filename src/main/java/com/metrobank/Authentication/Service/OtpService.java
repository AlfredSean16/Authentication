package com.metrobank.Authentication.Service;

import com.metrobank.Authentication.Entity.OtpSession;
import com.metrobank.Authentication.Entity.User;
import com.metrobank.Authentication.Repository.OtpSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {
    private final OtpSessionRepository otpSessionRepository;
    private final JavaMailSender mailSender;

    public OtpService(OtpSessionRepository otpSessionRepository, JavaMailSender mailSender) {
        this.otpSessionRepository = otpSessionRepository;
        this.mailSender = mailSender;
    }

    private final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        int otp = 100000 + random.nextInt(900000); // 6-digit OTP
        return String.valueOf(otp);
    }

    @Transactional
    public void sendOtp(User user) {
        // Clean up any existing OTP sessions for this user
        otpSessionRepository.deleteByUser(user);

        String otpCode = generateOtp();
        OtpSession otpSession = OtpSession.builder()
                .user(user)
                .otpCode(otpCode)
                .expiryTime(LocalDateTime.now().plusMinutes(5))
                .isVerified(false)
                .failedOtpAttempts(0)
                .build();

        otpSessionRepository.save(otpSession);

        switch (user.getOtpPreference()) {
            case EMAIL -> sendEmailOtp(user.getEmail(), otpCode);
            case SMS -> sendSmsOtp(user.getPhoneNumber(), otpCode);
        }
    }

    private void sendEmailOtp(String email, String otpCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your OTP Code");
        message.setText("Your OTP code is: " + otpCode + ". This code will expire in 5 minutes.");
        mailSender.send(message);
    }

    private void sendSmsOtp(String phoneNumber, String otpCode) {
        // Implement SMS sending logic here
        // For demo purposes, we'll just log it
        System.out.println("SMS OTP to " + phoneNumber + ": " + otpCode);
        // You can integrate with services like Twilio, AWS SNS, etc.
    }

    public boolean verifyOtp(User user, String otpCode) {
        Optional<OtpSession> sessionOpt = otpSessionRepository
                .findByUserAndOtpCodeAndIsVerifiedFalse(user, otpCode);

        if (sessionOpt.isEmpty()) return false;

        OtpSession session = sessionOpt.get();

        // Check expiry
        if (session.isExpired()) {
            otpSessionRepository.delete(session);
            return false;
        }

        // Check max attempts
        int MAX_ATTEMPTS = 3;
        if (session.getFailedOtpAttempts() >= MAX_ATTEMPTS) {
            otpSessionRepository.delete(session);
            return false;
        }

        // Verify OTP
        if (otpCode.equals(session.getOtpCode())) {
            session.setVerified(true);
            otpSessionRepository.save(session);
            return true;
        } else {
            session.setFailedOtpAttempts(session.getFailedOtpAttempts() + 1);
            otpSessionRepository.save(session);
            return false;
        }
    }
}
