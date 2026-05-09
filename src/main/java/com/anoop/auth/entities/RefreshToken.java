package com.anoop.auth.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Document(collection = "refresh_tokens")
public class RefreshToken {
    @Id
    private UUID id;
    private String jti;
    private User user;
    private Instant createdAt;
    private Instant expiresAt;
    private boolean revoked;
    private String replacedByToken;
}
