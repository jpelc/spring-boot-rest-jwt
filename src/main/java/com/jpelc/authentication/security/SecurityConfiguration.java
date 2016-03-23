package com.jpelc.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final TokenAuthenticationService tokenAuthenticationService;
    private final UserService userService;

    public SecurityConfiguration() {
        super(true);
        this.userService = new UserService();
        this.userService.addUser(new User("jpelc", "$2a$04$mHa2ANVoeoUIDp5x/Ut64.srQEOzKW4ed7GmFJ.DOlw3iFCLS1lmu", Collections.emptyList()));

        this.tokenAuthenticationService = new TokenAuthenticationService("secret-value", userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .exceptionHandling()
                .and()
                .anonymous()
                .and()
                .servletApi()
                .and()
                .headers().cacheControl().disable()
                .and()
                .authorizeRequests()

                // Allow anonymous resource requests
                .antMatchers("/").permitAll()
                .antMatchers("/favicon.ico").permitAll()
                .antMatchers("**/*.html").permitAll()
                .antMatchers("**/*.css").permitAll()
                .antMatchers("**/*.js").permitAll()

                // Allow anonymous logins
                .antMatchers("/auth/**").permitAll()

                // All other request need to be authenticated
                .anyRequest().authenticated()
                .and()

                // custom JSON based authentication by POST of {"username":"<name>","password":"<password>"}
                .addFilterBefore(loginFilter(), UsernamePasswordAuthenticationFilter.class)

                // Custom Token based authentication based on the header previously given to the client
                .addFilterBefore(new AuthenticationFilter(tokenAuthenticationService()), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return userService;
    }

    @Bean
    public TokenAuthenticationService tokenAuthenticationService() {
        return tokenAuthenticationService;
    }

    @Bean
    public LoginFilter loginFilter() {
        LoginFilter loginFilter = new LoginFilter("/auth/login", userDetailsService(), tokenAuthenticationService());
        try {
            loginFilter.setAuthenticationManager(authenticationManager());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return loginFilter;
    }

//    @Bean
//    public AuthenticationFilter authenticationFilter() {
//        return ;
//    }
}
