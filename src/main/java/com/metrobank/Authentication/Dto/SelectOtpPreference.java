package com.metrobank.Authentication.Dto;

import com.metrobank.Authentication.Entity.OtpPreference;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SelectOtpPreference {
    private String username;
    private OtpPreference otpPreference;
}
