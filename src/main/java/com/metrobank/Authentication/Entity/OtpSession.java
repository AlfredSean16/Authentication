package com.metrobank.Authentication.Entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
@Table(name = "otp_sessions")
public class OtpSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "OTP code cannot be blank")
    @Column(nullable = false)
    private String otpCode;

    @NotNull(message = "Expiry time is required")
    @Future(message = "Expiry time must be in the future")
    @Column(nullable = false)
    private LocalDateTime expiryTime;

    @Builder.Default
    private boolean isVerified = false;

    @Builder.Default
    private int failedOtpAttempts = 0;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @NotNull(message = "User is required")
    @OneToOne(fetch = FetchType.LAZY) // One Otp can belong to one user
    @JoinColumn(name = "user_id", nullable = false) // foreign key column in DB
    private User user;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryTime);
    }
}
