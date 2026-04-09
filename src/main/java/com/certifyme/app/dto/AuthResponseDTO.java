package com.certifyme.app.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {
    private String token;
    private UserResponseDTO user;
    private boolean otpRequired;
    private Long remainingValiditySeconds;
    private Long resendCooldownSeconds;

    // Manual constructors to maintain compatibility with existing service calls
    public AuthResponseDTO(String token, UserResponseDTO user) {
        this.token = token;
        this.user = user;
        this.otpRequired = false;
    }

    public AuthResponseDTO(String token, UserResponseDTO user, boolean otpRequired) {
        this.token = token;
        this.user = user;
        this.otpRequired = otpRequired;
    }
}
