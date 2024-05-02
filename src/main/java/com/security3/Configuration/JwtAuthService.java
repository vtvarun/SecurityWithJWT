package com.security3.Configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthService extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    AccessUserDetailsFromDataBase accessUserDetailsFromDataBase;

    Logger logger = LoggerFactory.getLogger(JwtAuthService.class);



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //get the author header
        logger.info("Inside do filter internal");
        String authHeader = request.getHeader("Authorization");

        String token = null;

        String username = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")){
            logger.info("token is not null");
            token = authHeader.substring(7);
            logger.info("Token "+token);
            username = jwtService.extractUsername(token);
            logger.info("Username "+username);
        }

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // It means the jwt is not verified and we have to verify it
            logger.info("security context is null");
            UserDetails userDetails = accessUserDetailsFromDataBase.loadUserByUsername(username);

            if(jwtService.validateToken(token,userDetails)){
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info("Authorities :"+userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(auth);
                logger.info("Put authentication object into security context");
            }

        }
        logger.info("Out side the chain");

        filterChain.doFilter(request,response);

    }
}
