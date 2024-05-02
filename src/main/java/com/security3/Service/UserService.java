package com.security3.Service;

import com.security3.DTO.ChangeEmailDTO;
import com.security3.Model.UserTable;
import com.security3.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    public UserTable addUser(UserTable userTable) {
        userTable.setPassword(passwordEncoder.encode(userTable.getPassword()));
        return userRepository.save(userTable);
    }

    public void deleteUser(Integer id) {
        userRepository.deleteById(id);
    }

    public void changeEmail(ChangeEmailDTO changeEmailDTO) {
        UserTable userTable = userRepository.findById(changeEmailDTO.getUserId()).orElse(null);

        userTable.setEmail(changeEmailDTO.getNewEmail());

        userRepository.save(userTable);
    }
}
