package com.metrobank.Authentication.Service;

import com.metrobank.Authentication.Entity.OtpSession;
import com.metrobank.Authentication.Entity.User;
import com.metrobank.Authentication.Repository.OtpSessionRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {
    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);

    private final OtpSessionRepository otpSessionRepository;
    private final JavaMailSender mailSender;
    private final SecureRandom random = new SecureRandom();

    private static final int MAX_OTP_ATTEMPTS = 3;

    public OtpService(OtpSessionRepository otpSessionRepository, JavaMailSender mailSender) {
        this.otpSessionRepository = otpSessionRepository;
        this.mailSender = mailSender;
    }

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

        try {
            switch (user.getOtpPreference()) {
                case EMAIL -> sendEmailOtp(user.getEmail(), otpCode);
                case SMS -> sendSmsOtp(user.getPhoneNumber(), otpCode);
            }
            logger.info("OTP sent successfully to user: {}", user.getUsername());
        } catch (Exception e) {
            logger.error("Failed to send OTP to user: {}. Error: {}", user.getUsername(), e.getMessage());
            throw new RuntimeException("Failed to send OTP. Please try again later.");
        }
    }

    private void sendEmailOtp(String email, String otpCode) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Your MetroBank eITR Login OTP Code");
            message.setText("Your OTP code is: " + otpCode +
                    "\n\nThis code will expire in 5 minutes." +
                    "\n\nFor security reasons, do not share this code with anyone." +
                    "\n\nIf you did not request this code, please contact support immediately.");
            mailSender.send(message);
            logger.info("Email OTP sent successfully to: {}", email);
        } catch (Exception e) {
            logger.error("Failed to send email OTP to: {}. Error: {}", email, e.getMessage());
            throw new RuntimeException("Failed to send email OTP");
        }
    }

    private void sendSmsOtp(String phoneNumber, String otpCode) {
        // For demo purposes, we'll just log it
        // In production, integrate with SMS service like Twilio, AWS SNS, etc.
        try {
            logger.info("SMS OTP would be sent to {}: {}", phoneNumber, otpCode);
            System.out.println("SMS OTP to " + phoneNumber + ": " + otpCode);

            // TODO: Implement actual SMS sending logic here
            // Example with Twilio:
            // twilioService.sendSms(phoneNumber, "Your MetroBank eITR OTP code is: " + otpCode + ". Valid for 5 minutes.");

        } catch (Exception e) {
            logger.error("Failed to send SMS OTP to: {}. Error: {}", phoneNumber, e.getMessage());
            throw new RuntimeException("Failed to send SMS OTP");
        }
    }

    @Transactional
    public boolean verifyOtp(User user, String otpCode) {
        Optional<OtpSession> sessionOpt = otpSessionRepository
                .findByUserAndOtpCodeAndIsVerifiedFalse(user, otpCode);

        if (sessionOpt.isEmpty()) {
            logger.warn("OTP verification failed for user: {} - OTP not found or already verified", user.getUsername());
            return false;
        }

        OtpSession session = sessionOpt.get();

        // Check expiry
        if (session.isExpired()) {
            logger.warn("OTP verification failed for user: {} - OTP expired", user.getUsername());
            otpSessionRepository.delete(session);
            return false;
        }

        // Check max attempts
        if (session.getFailedOtpAttempts() >= MAX_OTP_ATTEMPTS) {
            logger.warn("OTP verification failed for user: {} - Max attempts reached", user.getUsername());
            otpSessionRepository.delete(session);
            return false;
        }

        // Verify OTP
        if (otpCode.equals(session.getOtpCode())) {
            session.setVerified(true);
            otpSessionRepository.save(session);
            logger.info("OTP verified successfully for user: {}", user.getUsername());
            return true;
        } else {
            session.setFailedOtpAttempts(session.getFailedOtpAttempts() + 1);
            otpSessionRepository.save(session);
            logger.warn("OTP verification failed for user: {} - Invalid OTP. Attempts: {}/{}",
                    user.getUsername(), session.getFailedOtpAttempts(), MAX_OTP_ATTEMPTS);
            return false;
        }
    }

    @Transactional
    public void cleanupExpiredOtpSessions() {
        // This method can be called periodically to clean up expired sessions
        // You can implement this with @Scheduled annotation
        try {
            // Delete expired sessions
            otpSessionRepository.deleteAll(
                    otpSessionRepository.findAll().stream()
                            .filter(OtpSession::isExpired)
                            .toList()
            );
            logger.info("Cleaned up expired OTP sessions");
        } catch (Exception e) {
            logger.error("Error cleaning up expired OTP sessions: {}", e.getMessage());
        }
    }
}
