package com.inf1r.pract2.Models;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    USER, ADMIN, TEACHER;

    @Override
    public String getAuthority(){
        return name();
    }
}
