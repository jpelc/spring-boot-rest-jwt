package com.jpelc.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
class AuthenticationFilter extends GenericFilterBean {

    @Autowired
    private TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        logger.info("AuthenticationFilter");
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        Authentication authentication = null;
        try {
            logger.info("Before authentication");
            authentication = tokenAuthenticationService.getAuthentication(httpRequest);
            logger.info("After authentication");
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (AuthenticationException authenticationException) {
            logger.info("Authentication exception");
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
