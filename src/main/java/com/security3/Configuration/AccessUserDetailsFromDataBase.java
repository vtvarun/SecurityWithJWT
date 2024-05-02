package com.security3.Configuration;

import com.security3.Model.UserTable;
import com.security3.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AccessUserDetailsFromDataBase implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserTable userTable = userRepository.findByEmail(username);

        //I have to convert userTable into UserDetails, because it only return UserDetails
        return new convertingUserIntoUserDetails(userTable);

    }
}
