package com.anoop.auth.controllers;

import com.anoop.auth.config.UserMapper;
import com.anoop.auth.dtos.LoginRequest;
import com.anoop.auth.dtos.TokenResponse;
import com.anoop.auth.dtos.UserDto;
import com.anoop.auth.entities.RefreshToken;
import com.anoop.auth.entities.User;
import com.anoop.auth.repositories.RefreshTokenRepository;
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

import java.sql.Ref;
import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenRepository refreshTokenRepository;

    //Login
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
      Authentication authentication = authenticate(loginRequest);
         User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if(!user.isEnable()){
            throw new BadCredentialsException("User account is disabled");
        }
        String jti= UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder().jtl(jti).
                user(user)
                .id(UUID.randomUUID())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
         refreshTokenRepository.save(refreshTokenOb);
         String token = jwtService.generateToken(user);
         String refreshToken = jwtService.refreshToken(user,refreshTokenOb.getJtl());
        TokenResponse tokenResponse = TokenResponse.of(token,refreshToken,jwtService.getAccessTtlSeconds(),userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
      return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        }catch (Exception ex) {
            throw new BadCredentialsException("Invalid email or password !!");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
