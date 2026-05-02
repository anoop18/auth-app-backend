package com.anoop.auth.service;

import com.anoop.auth.dtos.UserDto;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final UserService userService;
    private PasswordEncoder passwordEncoder;
    @Override
    public UserDto registerUser(UserDto userDto) {
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        return userService.createUser(userDto);
    }

    @Override
    public void logout(String refreshToken) {

    }
}
