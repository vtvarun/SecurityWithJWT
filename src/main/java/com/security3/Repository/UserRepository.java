package com.security3.Repository;

import com.security3.Model.UserTable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserTable,Integer> {

    UserTable findByEmail(String username);
}
