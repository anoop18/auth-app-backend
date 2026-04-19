package com.anoop.auth.dtos;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType,
        UserDto user
) {
    public static TokenResponse of (String accessToken,String refreshToken,long expiresIn,
                                    UserDto userDto){
        return new TokenResponse(accessToken,refreshToken,expiresIn,"Bearer",userDto);
    }
}
