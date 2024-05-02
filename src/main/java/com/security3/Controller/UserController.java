package com.security3.Controller;

import com.security3.Configuration.JwtService;
import com.security3.DTO.AuthRequest;
import com.security3.DTO.ChangeEmailDTO;
import com.security3.Model.UserTable;
import com.security3.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public String welcome(){
        return "Welcome to User Portal";
    }

    @PostMapping("/add-user")
    public UserTable addUser(@RequestBody UserTable userTable){
        return userService.addUser(userTable);
    }

    @DeleteMapping("/delete-user/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String deleteUser(@PathVariable Integer id){
        userService.deleteUser(id);
        return "User has been deleted";
    }

    @PatchMapping("/change-email")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String changeEmail(@RequestBody ChangeEmailDTO changeEmailDTO){
        userService.changeEmail(changeEmailDTO);
        return "Email Id has been changed";
    }

    @PostMapping("/authenticate")
    public String createJWToken(@RequestBody AuthRequest authRequest){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(),authRequest.getPassword()));
        if(authentication.isAuthenticated()) return jwtService.createToken(authRequest.getUsername());
        return "User cannot be authenticated";
    }


}
