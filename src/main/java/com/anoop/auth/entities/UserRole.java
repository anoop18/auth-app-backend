package com.anoop.auth.entities;

import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Document("user_roles")
public class UserRole {
    private UUID id=UUID.randomUUID();
    private UUID userId;
    private UUID roleId;
}
