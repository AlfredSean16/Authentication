package com.metrobank.Authentication.Dto;
import lombok.*;
import lombok.experimental.Tolerate;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TotpSetupResponse {
    private String secret;
    private String qrCodeUrl;
    private String qrCodeImage; // Base64 encoded image
    private String issuer;
    private String accountName;
    private String message;
    private boolean setupRequired;

    // Constructor for setup response
    @Tolerate
    public TotpSetupResponse(String secret, String qrCodeUrl, String qrCodeImage,
                             String issuer, String accountName) {
        this.secret = secret;
        this.qrCodeUrl = qrCodeUrl;
        this.qrCodeImage = qrCodeImage;
        this.issuer = issuer;
        this.accountName = accountName;
        this.setupRequired = true;
        this.message = "Please scan the QR code with Google Authenticator app";
    }
}
