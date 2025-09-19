package com.metrobank.Authentication.Service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.metrobank.Authentication.Entity.User;
import com.metrobank.Authentication.Repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.KeyRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
public class TotpService {
    private static final Logger logger = LoggerFactory.getLogger(TotpService.class);

    private final GoogleAuthenticator googleAuthenticator;
    private final UserRepository userRepository;

    private static final String ISSUER = "MetroBank eITR";
    private static final int QR_CODE_SIZE = 300;

    public TotpService(UserRepository userRepository) {
        this.userRepository = userRepository;

        // Configure Google Authenticator
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder configBuilder =
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                        .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30))
                        .setWindowSize(1) // Allow 1 window tolerance (30 seconds before/after)
                        .setCodeDigits(6)
                        .setKeyRepresentation(KeyRepresentation.BASE32);

        this.googleAuthenticator = new GoogleAuthenticator(configBuilder.build());
    }

    /**
     * Generate a new TOTP secret for a user
     */
    @Transactional
    public String generateTotpSecret(User user) {
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secret = key.getKey();

        user.setTotpSecret(secret);
        user.setTotpEnabled(false); // Will be enabled after first successful verification
        userRepository.save(user);

        logger.info("TOTP secret generated for user: {}", user.getUsername());
        return secret;
    }

    /**
     * Generate QR code URL for Google Authenticator
     */
    public String generateQrCodeUrl(User user) {
        if (user.getTotpSecret() == null) {
            throw new RuntimeException("TOTP secret not found for user: " + user.getUsername());
        }

        String encodedIssuer = URLEncoder.encode(ISSUER, StandardCharsets.UTF_8);
        String encodedAccountName = URLEncoder.encode(user.getUsername() + " (" + user.getName() + ")", StandardCharsets.UTF_8);

        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                encodedIssuer,
                encodedAccountName,
                user.getTotpSecret(),
                encodedIssuer
        );
    }

    /**
     * Generate QR code as base64 image
     */
    public String generateQrCodeImage(User user) throws WriterException, IOException {
        String qrCodeUrl = generateQrCodeUrl(user);

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUrl, BarcodeFormat.QR_CODE, QR_CODE_SIZE, QR_CODE_SIZE);

        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ImageIO.write(qrImage, "PNG", outputStream);

        byte[] imageBytes = outputStream.toByteArray();
        return Base64.getEncoder().encodeToString(imageBytes);
    }

    /**
     * Verify TOTP code
     */
    @Transactional
    public boolean verifyTotpCode(User user, String totpCode) {
        if (user.getTotpSecret() == null) {
            logger.warn("TOTP verification failed for user: {} - No TOTP secret", user.getUsername());
            return false;
        }

        try {
            int code = Integer.parseInt(totpCode);
            boolean isValid = googleAuthenticator.authorize(user.getTotpSecret(), code);

            if (isValid) {
                logger.info("TOTP verification successful for user: {}", user.getUsername());

                // Enable TOTP if this is the first successful verification
                if (!user.isTotpEnabled()) {
                    user.completeTotpSetup();
                    userRepository.save(user);
                    logger.info("TOTP setup completed for user: {}", user.getUsername());
                }

                return true;
            } else {
                logger.warn("TOTP verification failed for user: {} - Invalid code", user.getUsername());
                return false;
            }
        } catch (NumberFormatException e) {
            logger.warn("TOTP verification failed for user: {} - Invalid code format", user.getUsername());
            return false;
        }
    }

    /**
     * Check if user has TOTP enabled
     */
    public boolean isTotpEnabled(User user) {
        return user.isTotpEnabled() && user.getTotpSecret() != null;
    }

    /**
     * Check if user requires TOTP setup
     */
    public boolean requiresTotpSetup(User user) {
        return user.requiresTotpSetup();
    }

    /**
     * Disable TOTP for a user
     */
    @Transactional
    public void disableTotp(User user) {
        user.setTotpSecret(null);
        user.setTotpEnabled(false);
        user.setTotpSetupRequired(true);
        userRepository.save(user);

        logger.info("TOTP disabled for user: {}", user.getUsername());
    }

    /**
     * Reset TOTP secret (for recovery purposes)
     */
    @Transactional
    public String resetTotpSecret(User user) {
        logger.info("Resetting TOTP secret for user: {}", user.getUsername());
        return generateTotpSecret(user);
    }

    /**
     * Get current time window for debugging purposes
     */
    public long getCurrentTimeWindow() {
        return System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(30);
    }
}
