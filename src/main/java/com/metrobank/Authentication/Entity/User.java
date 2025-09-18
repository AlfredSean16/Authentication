package com.metrobank.Authentication.Entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Name is required")
    @Size(max = 100, message = "Name must not exceed 100 characters")
    @Column(nullable = false)
    private String name;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank(message = "Password is required")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must be at least 8 characters long, contain one uppercase, one lowercase, one number, and one special character"
    )
    @Column(nullable = false)
    private String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 150, message = "Email must not exceed 150 characters")
    @Column(unique = true, nullable = false)
    private String email;

    @Pattern(
            regexp = "^(\\+63|0)9\\d{9}$",
            message = "Phone number must be a valid Philippine number (e.g. +639123456789 or 09123456789)"
    )
    @Column(unique = true)
    private String phoneNumber;

    @NotNull(message = "Role is required")
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Enumerated(EnumType.STRING)
    private OtpPreference otpPreference;

    @Builder.Default
    private boolean isAccountLocked = false;

    @Builder.Default
    private int failedLoginAttempts = 0;

    //New fields for cooldown management
    private LocalDateTime lockoutEndTime;

    @Builder.Default
    private int failedOtpAttempts = 0;

    private LocalDateTime otpCooldownEndTime;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    //Helper methods for account locking
    public boolean isLoginCooldownActive() {
        return lockoutEndTime != null && LocalDateTime.now().isBefore(lockoutEndTime);
    }

    public boolean isOtpCooldownActive() {
        return otpCooldownEndTime != null && LocalDateTime.now().isBefore(otpCooldownEndTime);
    }

    public void lockAccount() {
        this.isAccountLocked = true;
        this.lockoutEndTime = LocalDateTime.now().plusDays(1); // 1 day cooldown
    }

    public void unlockAccount() {
        this.isAccountLocked = false;
        this.lockoutEndTime = null;
        this.failedLoginAttempts = 0;
    }

    public void setOtpCooldown() {
        this.otpCooldownEndTime = LocalDateTime.now().plusMinutes(30); // 30 minute cooldown
        this.failedOtpAttempts = 0;
    }

    public void clearOtpCooldown() {
        this.otpCooldownEndTime = null;
        this.failedOtpAttempts = 0;
    }

    // Check if password is default
    public boolean hasDefaultPassword() {
        return password != null && (password.contains("DefaultPassword123"));
    }
}
