package com.certifyme.app.service;
import com.certifyme.app.model.Role;
import com.certifyme.app.dto.AuthResponseDTO;
import com.certifyme.app.dto.LoginRequestDTO;
import com.certifyme.app.dto.RegisterRequestDTO;
import com.certifyme.app.dto.UserResponseDTO;
import com.certifyme.app.exception.DuplicateResourceException;
import com.certifyme.app.exception.UnauthorizedException;
import com.certifyme.app.mapper.UserMapper;
import com.certifyme.app.model.User;
import com.certifyme.app.repository.UserRepository;
import com.certifyme.app.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponseDTO register(RegisterRequestDTO request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("Email already in use");
        }

        User user = userMapper.toEntity(request);

        user.setPassword(passwordEncoder.encode(request.getPassword()));

        // 👇 IMPORTANT CHANGE
        if (request.getRole() != null) {
            user.setRole(request.getRole());
        } else {
            user.setRole(Role.STUDENT); // default role
        }

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);
        UserResponseDTO userDTO = userMapper.toResponseDTO(user);
        
        return new AuthResponseDTO(jwtToken, userDTO);
    }

    public AuthResponseDTO login(LoginRequestDTO request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid email or password");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        String jwtToken = jwtService.generateToken(user);
        UserResponseDTO userDTO = userMapper.toResponseDTO(user);

        return new AuthResponseDTO(jwtToken, userDTO);
    }
}
