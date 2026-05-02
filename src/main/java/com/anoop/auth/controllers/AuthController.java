package com.anoop.auth.controllers;

import com.anoop.auth.config.UserMapper;
import com.anoop.auth.dtos.LoginRequest;
import com.anoop.auth.dtos.RefreshTokenRequest;
import com.anoop.auth.dtos.TokenResponse;
import com.anoop.auth.dtos.UserDto;
import com.anoop.auth.entities.RefreshToken;
import com.anoop.auth.entities.User;
import com.anoop.auth.repositories.RefreshTokenRepository;
import com.anoop.auth.repositories.UserRepository;
import com.anoop.auth.security.CookieService;
import com.anoop.auth.security.JwtService;
import com.anoop.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.sql.Ref;
import java.time.Instant;
import java.util.Optional;
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
    private final CookieService cookieService;

    //Login
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        Authentication authentication = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if (!user.isEnable()) {
            throw new BadCredentialsException("User account is disabled");
        }
        String jti = UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder().jtl(jti).
                user(user)
                .id(UUID.randomUUID())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenOb);
        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.refreshToken(user, refreshTokenOb.getJtl());
        //use cookie service to attach refresh cookie
        cookieService.attachRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeader(response);
        TokenResponse tokenResponse = TokenResponse.of(token, refreshToken, jwtService.getAccessTtlSeconds(), userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception ex) {
            throw new BadCredentialsException("Invalid email or password !!");
        }
    }
    @PostMapping("/new")
    public ResponseEntity<?> getMapping (){
        return ResponseEntity.ok("Hello from auth controller");
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest body,
                                                      HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readRefreshTokenFromRequest(body, request).orElseThrow(() -> new BadCredentialsException("Refresh token is missing"));
        if(!jwtService.isRefreshToken(refreshToken)){
            throw new BadCredentialsException("Invalid refresh token");
        }
        var refreshTokenOb = jwtService.validateToken(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
      RefreshToken storedRefreshToken =  refreshTokenRepository.findById(userId)
                .orElseThrow(() -> new BadCredentialsException("Refresh token not found in database"));
        if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token is revoked or expired");
        }
        if(!storedRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Refresh token does not belong to the user");
        }
        User user = storedRefreshToken.getUser();
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.refreshToken(user, storedRefreshToken.getJtl());
        //update refresh token in database
        storedRefreshToken.setJtl(UUID.randomUUID().toString());
        storedRefreshToken.setCreatedAt(Instant.now());
        storedRefreshToken.setExpiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()));
        refreshTokenRepository.save(storedRefreshToken);
        //use cookie service to attach refresh cookie
        cookieService.attachRefreshCookie(response, newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeader(response);
        TokenResponse tokenResponse = TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTtlSeconds(), userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);
    }


    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }


    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        var cookies = request.getCookies();
        if (cookies != null) {
            for (var cookie : cookies) {
                if (cookie.getName().equals(cookieService.getRefreshTokenCookieName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String candidate = authHeader.substring(7);
            if(!candidate.isEmpty()){
                try {
                    if(jwtService.isRefreshToken(candidate)){
                        return Optional.of(candidate);
                    }
                }catch (Exception ex){
                    throw new BadCredentialsException("Invalid refresh token in Authorization header");
                }
            }
            return Optional.of(authHeader.substring(7));
        }
        throw new BadCredentialsException("Refresh token is missing");
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        //read refresh token from cookie
        var cookies = request.getCookies();
        if (cookies != null) {
            for (var cookie : cookies) {
                if (cookie.getName().equals(cookieService.getRefreshTokenCookieName())) {
                    String refreshToken = cookie.getValue();
                    authService.logout(refreshToken);
                    cookieService.clearRefreshCookie(response);
                    cookieService.addNoStoreHeader(response);
                    break;
                }
            }
        }
        return ResponseEntity.noContent().build();
    }
}