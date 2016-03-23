package com.jpelc.authentication.security;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;

@Service
class UserService implements UserDetailsService {

    private final AccountStatusUserDetailsChecker detailsChecker = new AccountStatusUserDetailsChecker();
    private final HashMap<String, User> userMap = new HashMap<>();

    public UserService() {
        User user = new User("jpelc", "$2a$04$mHa2ANVoeoUIDp5x/Ut64.srQEOzKW4ed7GmFJ.DOlw3iFCLS1lmu", Collections.emptyList());
        userMap.put(user.getUsername(), user);
    }

    @Override
    public final User loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = userMap.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("user not found");
        }
        detailsChecker.check(user);
        return user;
    }

    void addUser(User user) {
        userMap.put(user.getUsername(), user);
    }

}
