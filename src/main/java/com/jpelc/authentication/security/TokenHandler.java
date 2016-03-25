package com.jpelc.authentication.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Calendar;

@Component
class TokenHandler {

    private static final int EXPIRATION_TIME_IN_DAYS = 7;
    private static final String AUDIENCE = "https://example.com";
    private static final String ISSUER = "AppName";

    @Value("c2VjcmV0")
    private String secret;

    @Autowired
    private UserService userService;

    User parseUserFromToken(String token) {
        Jws<Claims> jws = Jwts.parser()
                .requireAudience(AUDIENCE)
                .requireIssuer(ISSUER)
                .setSigningKey(secret)
                .parseClaimsJws(token);

        String username = jws.getBody().getSubject();
        return userService.loadUserByUsername(username);
    }

    String createTokenForUser(User user) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 3);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(user.getUsername())
                .setAudience(AUDIENCE)
                .setIssuer(ISSUER)
                .setExpiration(calendar.getTime())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

}
