package com.metrobank.Authentication.Entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.Tolerate;
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
@Table(name = "login_attempts")
public class LoginAttempt {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ipAddress;
    private String userAgent;
    private boolean successful;
    private String failureReason;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime attemptTime;

    @NotNull(message = "User is required")
    @ManyToOne(fetch = FetchType.LAZY) // Many login attempts can belong to one user
    @JoinColumn(name = "user_id", nullable = false) // foreign key column in DB
    private User user;

    // Custom constructor for quick creation
    @Tolerate
    public LoginAttempt(User user, String ipAddress, String userAgent, boolean successful, String failureReason) {
        this.user = user;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.successful = successful;
        this.failureReason = failureReason;
        this.attemptTime = LocalDateTime.now();
    }
}
