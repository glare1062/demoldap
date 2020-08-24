package com.example.demo;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeContorller {

    @GetMapping("/")
    public String index(){
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Object rawPassword  = SecurityContextHolder.getContext().getAuthentication().getCredentials();
        Object details = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
        return "welcome  to  home page =+"+username+rawPassword+details;
    }

}
