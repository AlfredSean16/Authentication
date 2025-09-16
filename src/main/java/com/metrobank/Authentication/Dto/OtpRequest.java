package com.metrobank.Authentication.Dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OtpRequest {
    @NotNull(message = "Username is required")
    private String username;

    @NotBlank(message = "OTP code cannot be blank")
    @Size(min = 6, max = 6, message = "OTP code must be exactly 6 digits")
    @Pattern(regexp = "\\d{6}", message = "OTP code must contain only numbers")
    private String otpCode;
}
