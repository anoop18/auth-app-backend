package com.anoop.auth.config;

import com.anoop.auth.dtos.UserDto;
import com.anoop.auth.entities.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
   @Mapping(target = "password", ignore = true)
    UserDto toDto(User user);

    User toEntity(UserDto dto);
}
