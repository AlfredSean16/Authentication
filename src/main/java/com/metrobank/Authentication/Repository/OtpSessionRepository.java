package com.metrobank.Authentication.Repository;

import com.metrobank.Authentication.Entity.OtpSession;
import com.metrobank.Authentication.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpSessionRepository extends JpaRepository<OtpSession, Long> {
    Optional<OtpSession> findByUserAndOtpCodeAndIsVerifiedFalse(User user, String otpCode);
    void deleteByUser(User user);
}
