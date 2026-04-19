package com.anoop.auth.security;

import com.anoop.auth.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;


import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;


@Service
@Getter
@Setter
public class JwtService {
    @Value("${security.jwt.secret}")
    private String secret;
    @Value("${security.jwt.refresh-ttl-seconds}")
    private  long accessTtlSeconds;
    @Value("${security.jwt.refresh-ttl-seconds}")
    private  long refreshTtlSeconds;
    @Value("${security.jwt.issuer}")
    private  String issuer;
    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

//    public JwtService(String secret,long accessTtlSeconds, long refreshTtlSeconds, String secretKey, String issuer) {
//        if(secretKey==null || secretKey.length()<64 ){
//            throw new IllegalArgumentException("Invalid Secret");
//        }
//        this.accessTtlSeconds = accessTtlSeconds;
//        this.refreshTtlSeconds = refreshTtlSeconds;
//       // this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
//        this.issuer = issuer;
//
//    }
    public String generateToken(User user){
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream().toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .claim("roles", roles)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds)))
                .signWith(getKey(), Jwts.SIG.HS256)
                .compact();

    }
    public String refreshToken(User user,String refreshToken ){
        Instant now = Instant.now();
        return Jwts.builder()
                .id(refreshToken)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .signWith(getKey(), Jwts.SIG.HS256)
                .compact();
    }

     public Jws<Claims> validateToken(String token){
         try {
            return Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token);
        }catch (Exception e){
            throw new IllegalArgumentException("Invalid Token");
        }
     }
     public boolean isAccessToken(String token) {
         try {
             Claims claims = validateToken(token).getPayload();
             return "access".equals(claims.get("typ"));
         } catch (Exception e) {
             return false;
         }
     }
         public boolean isRefreshToken(String token){
             try {
                 Claims claims = validateToken(token).getPayload();
                 return "refresh".equals(claims.get("typ"));
             }catch (Exception e){
                 return false;
             }
    }
    public UUID getUserId(String token){
        try {
            Claims claims = validateToken(token).getPayload();
            return UUID.fromString(claims.getSubject());
        }catch (Exception e){
            throw new IllegalArgumentException("Invalid Token");
        }
    }
    public String getJti(String token) {
        try {
            return validateToken(token).getPayload().getId();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid Token");
        }
    }
   public List<GrantedAuthority> getAuthoritiesFromToken(String token){
        try {
            Claims claims = validateToken(token).getPayload();
            List<String> roles = claims.get("roles", List.class);
            return roles.stream()
                    .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid Token");
        }
    }

}

