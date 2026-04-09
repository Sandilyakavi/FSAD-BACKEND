package com.certifyme.app.mapper;

import com.certifyme.app.dto.RegisterRequestDTO;
import com.certifyme.app.dto.UserResponseDTO;
import com.certifyme.app.model.Role;
import com.certifyme.app.model.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public User toEntity(RegisterRequestDTO dto) {
        return User.builder()
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .email(dto.getEmail())
                .password(dto.getPassword()) // Will be encoded by AuthService
                .age(dto.getAge())
                .gender(dto.getGender() != null && !dto.getGender().isBlank() ? dto.getGender() : "Prefer not to say")
                .country(dto.getCountry())
                .studentId(dto.getStudentId())
                .role(Role.STUDENT)
                .build();
    }

    public UserResponseDTO toResponseDTO(User user) {
        UserResponseDTO dto = new UserResponseDTO();
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setMiddleName(user.getMiddleName());
        dto.setLastName(user.getLastName());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole());
        dto.setAge(user.getAge());
        dto.setGender(user.getGender());
        dto.setCountry(user.getCountry());
        dto.setStudentId(user.getStudentId());
        
        // Map certification count
        dto.setCertificationCount(user.getCertifications() != null ? user.getCertifications().size() : 0);
        
        return dto;
    }
}
