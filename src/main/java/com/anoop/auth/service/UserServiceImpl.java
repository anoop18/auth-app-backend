package com.anoop.auth.service;

import com.anoop.auth.config.UserMapper;
import com.anoop.auth.dtos.UserDto;
import com.anoop.auth.entities.Provider;
import com.anoop.auth.entities.User;
import com.anoop.auth.exceptions.ResourceNotFound;
import com.anoop.auth.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;


    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if(userDto.getEmail()==null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }
        if(userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("User with given email already exists");
        }
        User user = userMapper.toEntity(userDto);
        user.setProvider(userDto.getProvider() !=null ? userDto.getProvider() : Provider.LOCAL);
        user.setRoles(Set.of("USER"));
        user.setId(UUID.randomUUID());
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(user);
        return userMapper.toDto(savedUser);
    }

    @Override
    public UserDto updateUser(UserDto userDto, java.util.UUID userId) {
        User exstingUser = userRepository.findById(userId).orElseThrow(() -> new ResourceNotFound("User not found with given Id"));
        if(userDto.getName()!=null) exstingUser.setName(userDto.getName());
        if (userDto.getImage()!=null) exstingUser.setImage(userDto.getImage());
        if (userDto.getProvider()!=null) exstingUser.setProvider(userDto.getProvider());
        if(userDto.getPassword()!=null) exstingUser.setPassword(userDto.getPassword());
        exstingUser.setUpdatedAt(Instant.now());
        exstingUser.getRoles().add("ADMIN");
        User updatedUser = userRepository.save(exstingUser);
        return userMapper.toDto(updatedUser);
    }

    @Override
    public UserDto findUserByEmail(String email) {
       User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFound("User not found with given email Id"));
        return userMapper.toDto(user);
    }

    @Override
    public void deleteUser(java.util.UUID userId) {
       User user= userRepository.findById(userId).orElseThrow(() -> new ResourceNotFound("User not found with given Id"));
       userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(java.util.UUID userId) {
       User user= userRepository.findById(userId).orElseThrow(() -> new ResourceNotFound("User not found with given Id"));
        return userMapper.toDto(user) ;
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll().stream().map(userMapper::toDto).toList();
    }


}
