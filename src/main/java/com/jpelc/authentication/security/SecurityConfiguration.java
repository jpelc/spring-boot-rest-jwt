package com.jpelc.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationFilter authenticationFilter;

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
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
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    public LoginFilter loginFilter() {
        LoginFilter loginFilter = new LoginFilter("/auth/login");
        try {
            loginFilter.setAuthenticationManager(authenticationManager());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return loginFilter;
    }

    @Bean
    public FilterRegistrationBean filterRegistrationBean() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setEnabled(false);
        filterRegistrationBean.setFilter(authenticationFilter);
        return filterRegistrationBean;
    }
}
