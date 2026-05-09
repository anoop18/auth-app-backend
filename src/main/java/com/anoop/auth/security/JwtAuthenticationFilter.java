package com.anoop.auth.security;

import com.anoop.auth.repositories.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/v1/auth");
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      String header = request.getHeader("Authorization");
      if(header != null && header.startsWith("Bearer ")) {
          String token = header.substring(7);
          if(!jwtService.isAccessToken(token)){
              filterChain.doFilter(request,response);
              return;
          }
          try {
              Jws<Claims> parseClaim = jwtService.validateToken(token);
              Claims payload = parseClaim.getPayload();
              String userId = payload.getSubject();
              UUID userIdUuid = UUID.fromString(userId);
              List<GrantedAuthority> authorities = jwtService.getAuthoritiesFromToken(token);
              UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userIdUuid, null, authorities);
              authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
              SecurityContextHolder.getContext().setAuthentication(authenticationToken);


          } catch (ExpiredJwtException e) {
              request.setAttribute("error", "Token Expired");
          } catch (Exception e) {
              request.setAttribute("error", "Invalid Token");
          }
      }
            filterChain.doFilter(request, response);

    }
}
