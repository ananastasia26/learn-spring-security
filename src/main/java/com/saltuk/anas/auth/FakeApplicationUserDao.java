package com.saltuk.anas.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.saltuk.anas.security.ApplicationUserRole.*;


@Repository("fake")
public class FakeApplicationUserDao implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDao(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
        return getApplicationUsers().stream().filter(u -> u.getUsername().equals(username)).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> appUsers = List.of(
                new ApplicationUser("annasmith",
                        passwordEncoder.encode("password"),
                        STUDENT.getAuthority(),
                        true, true, true, true),
                new ApplicationUser("linda",
                        passwordEncoder.encode("password123"),
                        ADMIN.getAuthority(),
                        true, true, true, true),
                new ApplicationUser("tom",
                        passwordEncoder.encode("password123"),
                        ADMINTRAINEE.getAuthority(),
                        true, true, true, true)
        );

        return appUsers;
    }
}
