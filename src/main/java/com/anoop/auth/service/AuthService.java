package com.anoop.auth.service;

import com.anoop.auth.dtos.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);

    void logout(String refreshToken);
//    String loginUser(String email, String password);
//     void logoutUser(String token);
//     boolean isAuthenticated(String token);
}
