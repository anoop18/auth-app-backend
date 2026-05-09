package com.anoop.auth.repositories;

import com.anoop.auth.entities.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, UUID  > {
    Optional<RefreshToken> findByJti(String jti);

}
