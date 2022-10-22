package com.saltuk.anas.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.saltuk.anas.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Set.of()),
    ADMIN(Set.of(COURSE_READ,
            COURSE_WRITE,
            STUDENT_WRITE,
            STUDENT_READ)),
    ADMINTRAINEE(Set.of(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getAuthority() {
        var authorities = permissions.stream()
                .map(p -> new SimpleGrantedAuthority(p.getPermission()))
                .collect(Collectors.toSet());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
