package com.saltuk.anas.security;

public enum ApplicationUserPermission {
    STUDENT_WRITE("student:write"),
    STUDENT_READ("student:read"),
    COURSE_WRITE("student:write"),
    COURSE_READ("student:read");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
