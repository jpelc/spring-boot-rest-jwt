package com.jpelc.authentication.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

class LoginFilter extends AbstractAuthenticationProcessingFilter {

    private static final String PASSWORD_KEY = "password";
    private static final String USERNAME_KEY = "username";

    private TokenAuthenticationService tokenAuthenticationService;
    private UserDetailsService userDetailsService;

    LoginFilter(String defaultFilterProcessesUrl, UserDetailsService userDetailsService, TokenAuthenticationService tokenAuthenticationService) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl, "POST"));
        this.userDetailsService = userDetailsService;
        this.tokenAuthenticationService = tokenAuthenticationService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            JsonNode jsonObject = toJSONObject(request);

            String username = this.obtainUsername(jsonObject);
            String password = this.obtainPassword(jsonObject);

            if (username == null) {
                username = "";
            }

            if (password == null) {
                password = "";
            }

            username = username.trim();
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            this.setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Lookup the complete User object from the database and create an Authentication for it
        final User authenticatedUser = (User) userDetailsService.loadUserByUsername(authResult.getName());
        final UserAuthentication userAuthentication = new UserAuthentication(authenticatedUser, true);

        // Add the custom token as HTTP header to the response
        tokenAuthenticationService.addAuthentication(response, userAuthentication);

        // Add the authentication to the Security context
        SecurityContextHolder.getContext().setAuthentication(userAuthentication);
    }

    private JsonNode toJSONObject(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode;

        try (BufferedReader bufferedReader = request.getReader()) {
            jsonNode = objectMapper.readTree(bufferedReader);
        }

        return jsonNode;
    }

    private String obtainPassword(JsonNode jsonObject) {
        return jsonObject.get(PASSWORD_KEY).textValue();
    }

    private String obtainUsername(JsonNode jsonObject) {
        return jsonObject.get(USERNAME_KEY).textValue();
    }

    private void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }
}
