package com.jpelc.authentication.security;

import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Service
class TokenAuthenticationService {

    private static final String AUTH_HEADER_NAME = "X-AUTH-TOKEN";

    @Autowired
    private TokenHandler tokenHandler;

    void addAuthentication(HttpServletResponse response, UserAuthentication authentication) {
        final User user = (User) authentication.getDetails();
        response.addHeader(AUTH_HEADER_NAME, tokenHandler.createTokenForUser(user));
    }

    Authentication getAuthentication(HttpServletRequest request) {
        final Optional<String> token = Optional.ofNullable(request.getHeader(AUTH_HEADER_NAME));

        String tokenValue = token.orElseThrow(() -> new AuthenticationCredentialsNotFoundException("Token not found."));

        final Optional<User> user;
        try {
            user = Optional.ofNullable(tokenHandler.parseUserFromToken(tokenValue));
        } catch (JwtException e) {
            throw new AuthenticationCredentialsNotFoundException("Invalid.");
        }

        final User userValue = user.orElseThrow(() -> new AuthenticationCredentialsNotFoundException("User does not exist."));

        return new UserAuthentication(userValue, true);
    }

}
