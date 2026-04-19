package com.anoop.auth.dtos;

import com.anoop.auth.entities.Provider;
import lombok.*;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private UUID id;
    private String email;
    private String name;
    private String password;
    private String image;
    private boolean enable;
    private Instant createdAt;
    private Instant updatedAt;
    //private String gender;
    //priavte Address address;
    private Provider provider=Provider.LOCAL ;
    private Set<String> roles;

}
