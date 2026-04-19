package com.anoop.auth.service;

import com.anoop.auth.dtos.UserDto;
import java.util.UUID;

public interface UserService {
    UserDto createUser(UserDto userDto);
    UserDto updateUser(UserDto userDto, UUID userId);
    UserDto findUserByEmail(String email);
    void deleteUser(UUID userId);
    UserDto getUserById(UUID userId);
    Iterable <UserDto> getAllUsers();

}
