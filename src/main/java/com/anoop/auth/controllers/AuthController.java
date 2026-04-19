package com.anoop.auth.controllers;

import com.anoop.auth.config.UserMapper;
import com.anoop.auth.dtos.LoginRequest;
import com.anoop.auth.dtos.TokenResponse;
import com.anoop.auth.dtos.UserDto;
import com.anoop.auth.entities.User;
import com.anoop.auth.repositories.UserRepository;
import com.anoop.auth.security.JwtService;
import com.anoop.auth.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private JwtService jwtService;
    private final UserMapper userMapper;

    //Login
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
      Authentication authentication = authenticate(loginRequest);
         User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if(!user.isEnable()){
            throw new BadCredentialsException("User account is disabled");
        }
         String token = jwtService.generateToken(user);
        TokenResponse tokenResponse = TokenResponse.of(token,"",jwtService.getAccessTtlSeconds(),userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        }catch (Exception ex) {
            throw new IllegalArgumentException("Invalid email or password");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
